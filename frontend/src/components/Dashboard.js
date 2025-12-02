import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getPrivateKey } from '../utils/indexedDB';
import { importPrivateKeyJWK } from '../utils/crypto';
import { authAPI, kxAPI, messagesAPI } from '../services/api';
import {
  createKeyInit,
  processKeyInitAndCreateResp,
  processKeyRespAndDeriveKey,
  createKeyConfirm,
  decryptAndVerifyKeyConfirm
} from '../utils/keyExchange';
import { encryptMessage, decryptMessage } from '../utils/messageCrypto';
import './Dashboard.css';

const Dashboard = () => {
  const [username, setUsername] = useState('');
  const [hasPrivateKey, setHasPrivateKey] = useState(false);
  const [keyInfo, setKeyInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [peerUsername, setPeerUsername] = useState('');
  const [kxLog, setKxLog] = useState([]);
  const [kxContext, setKxContext] = useState(null);
  const [chatMessages, setChatMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [msgSeq, setMsgSeq] = useState(1);
  const navigate = useNavigate();

  useEffect(() => {
    const storedUsername = localStorage.getItem('username');
    if (!storedUsername) {
      navigate('/login');
      return;
    }

    setUsername(storedUsername);
    checkPrivateKey(storedUsername);
  }, [navigate]);

  const checkPrivateKey = async (username) => {
    try {
      setLoading(true);
      const privateKeyJWK = await getPrivateKey(username);
      
      // Try to import it to verify it's valid
      const privateKey = await importPrivateKeyJWK(
        privateKeyJWK,
        'RSASSA-PKCS1-v1_5'
      );
      
      setHasPrivateKey(true);
      setKeyInfo({
        algorithm: privateKeyJWK.alg || 'RSA-OAEP',
        keyType: privateKeyJWK.kty || 'RSA',
        keySize: '2048 bits'
      });
    } catch (error) {
      console.error('Private key check failed:', error);
      setHasPrivateKey(false);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    localStorage.removeItem('userId');
    navigate('/login');
  };

  const addLog = (msg) => {
    setKxLog((prev) => [`${new Date().toLocaleTimeString()}: ${msg}`, ...prev].slice(0, 20));
  };

  // Initiator: start key exchange with peer
  const handleStartKeyExchange = async () => {
    if (!peerUsername) {
      addLog('Please enter peer username');
      return;
    }
    try {
      addLog(`Starting key exchange with ${peerUsername} as initiator`);
      const { body, signature, context } = await createKeyInit(username, peerUsername);
      setKxContext({
        role: 'initiator',
        peer: peerUsername,
        keyInitBody: body,
        initContext: context,
        sessionId: body.sessionId,
        aesKey: null,
        transcriptHash: null
      });
      await kxAPI.sendMessage(peerUsername, 'KEY_INIT', { body, signature });
      addLog('KEY_INIT sent to server');
    } catch (error) {
      console.error('Key exchange start error:', error);
      addLog(`Error starting key exchange: ${error.message}`);
    }
  };

  // Poll inbox and process any pending KX messages
  const handleCheckInbox = async () => {
    try {
      const messages = await kxAPI.getInbox();
      if (!messages || messages.length === 0) {
        addLog('No key-exchange messages in inbox');
        return;
      }

      for (const msg of messages) {
        if (msg.messageType === 'KEY_INIT') {
          // We are responder (B)
          const { body, signature } = msg.payload;
          addLog(`Received KEY_INIT from ${msg.from}`);
          const initiatorInfo = await authAPI.getPublicKey(msg.from);
          const { body: respBody, signature: respSig, sessionContext } =
            await processKeyInitAndCreateResp(
              body,
              signature,
              initiatorInfo.publicKey,
              username
            );
          setKxContext({
            role: 'responder',
            peer: msg.from,
            keyInitBody: body,
            sessionId: body.sessionId,
            aesKey: sessionContext.aesKey,
            transcriptHash: sessionContext.transcriptHash,
            nonceA: sessionContext.nonceA,
            nonceB: sessionContext.nonceB
          });
          await kxAPI.sendMessage(msg.from, 'KEY_RESP', {
            body: respBody,
            signature: respSig
          });
          addLog('Processed KEY_INIT, sent KEY_RESP');
        } else if (msg.messageType === 'KEY_RESP' && kxContext && kxContext.role === 'initiator') {
          // Initiator receives response
          const { body, signature } = msg.payload;
          addLog(`Received KEY_RESP from ${msg.from}`);
          const responderInfo = await authAPI.getPublicKey(msg.from);
          const { aesKey, sessionId, transcriptHash } = await processKeyRespAndDeriveKey(
            body,
            signature,
            responderInfo.publicKey,
            kxContext.keyInitBody,
            kxContext.initContext
          );
          const updatedContext = {
            ...kxContext,
            aesKey,
            sessionId,
            transcriptHash
          };
          setKxContext(updatedContext);
          const confirmMsg = await createKeyConfirm(
            'KEY_CONFIRM_A',
            sessionId,
            username,
            msg.from,
            aesKey,
            transcriptHash
          );
          await kxAPI.sendMessage(msg.from, 'KEY_CONFIRM_A', confirmMsg);
          addLog('Derived session key and sent KEY_CONFIRM_A');
        } else if (msg.messageType === 'KEY_CONFIRM_A' && kxContext && kxContext.role === 'responder') {
          // Responder receives confirmation from initiator
          addLog(`Received KEY_CONFIRM_A from ${msg.from}`);
          await decryptAndVerifyKeyConfirm(
            msg.payload,
            kxContext.aesKey,
            kxContext.transcriptHash
          );
          addLog('KEY_CONFIRM_A verified, sending KEY_CONFIRM_B');
          const confirmB = await createKeyConfirm(
            'KEY_CONFIRM_B',
            kxContext.sessionId,
            username,
            msg.from,
            kxContext.aesKey,
            kxContext.transcriptHash
          );
          await kxAPI.sendMessage(msg.from, 'KEY_CONFIRM_B', confirmB);
        } else if (msg.messageType === 'KEY_CONFIRM_B' && kxContext && kxContext.role === 'initiator') {
          // Initiator receives final confirmation
          addLog(`Received KEY_CONFIRM_B from ${msg.from}`);
          await decryptAndVerifyKeyConfirm(
            msg.payload,
            kxContext.aesKey,
            kxContext.transcriptHash
          );
          addLog('KEY_CONFIRM_B verified. Secure session established!');
        } else {
          addLog(`Received unrelated KX message of type ${msg.messageType}`);
        }
      }
    } catch (error) {
      console.error('Inbox processing error:', error);
      addLog(`Error checking inbox: ${error.message}`);
    }
  };

  const canChat = kxContext && kxContext.aesKey && kxContext.peer;

  // Send encrypted chat message using established session key
  const handleSendMessage = async () => {
    if (!canChat || !newMessage.trim()) return;

    try {
      const peer = kxContext.peer;
      const sessionId = kxContext.sessionId;
      const currentSeq = msgSeq;

      const encrypted = await encryptMessage(
        kxContext.aesKey,
        sessionId,
        username,
        peer,
        currentSeq,
        newMessage.trim()
      );

      await messagesAPI.sendEncrypted({
        sessionId,
        to: peer,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        msgSeq: currentSeq,
        timestamp: encrypted.timestamp
      });

      // Display immediately in local chat
      setChatMessages((prev) => [
        ...prev,
        {
          from: username,
          to: peer,
          content: newMessage.trim(),
          timestamp: new Date(encrypted.timestamp)
        }
      ]);

      setMsgSeq(currentSeq + 1);
      setNewMessage('');
    } catch (error) {
      console.error('Send encrypted message error:', error);
      addLog(`Error sending encrypted message: ${error.message}`);
    }
  };

  // Load and decrypt conversation messages from server
  const handleLoadMessages = async () => {
    if (!canChat) return;

    try {
      const peer = kxContext.peer;
      const sessionId = kxContext.sessionId;
      const encryptedMessages = await messagesAPI.getConversation(peer, sessionId);

      const decrypted = [];
      for (const msg of encryptedMessages) {
        try {
          const plain = await decryptMessage(kxContext.aesKey, msg);
          decrypted.push({
            from: plain.from,
            to: plain.to,
            content: plain.content,
            timestamp: new Date(plain.timestamp)
          });
        } catch (err) {
          console.error('Decrypt message failed:', err);
          addLog('Failed to decrypt one message (possible tampering or wrong key).');
        }
      }

      setChatMessages(decrypted);
    } catch (error) {
      console.error('Load messages error:', error);
      addLog(`Error loading messages: ${error.message}`);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div style={styles.headerContent}>
          <h1 style={styles.headerTitle}>Secure Messaging Dashboard</h1>
          <button onClick={handleLogout} style={styles.logoutButton} className="dashboard-logout-button">
            Logout
          </button>
        </div>
      </div>

      <div style={styles.content}>
        <div style={styles.welcomeCard}>
          <div style={styles.welcomeIcon}>👋</div>
          <h2 style={styles.welcomeTitle}>Welcome, {username}</h2>
          <p style={styles.welcomeSubtitle}>Your secure messaging dashboard</p>
        </div>

        <div style={styles.cardsGrid}>
          {/* User Information Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>👤</span>
              <h3 style={styles.cardTitle}>User Information</h3>
            </div>
            <div style={styles.cardBody}>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Username:</span>
                <span style={styles.infoValue}>{username}</span>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Account Status:</span>
                <span style={styles.statusBadge}>Active</span>
              </div>
            </div>
          </div>

          {/* Key Status Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>🔑</span>
              <h3 style={styles.cardTitle}>Cryptographic Keys</h3>
            </div>
            <div style={styles.cardBody}>
              {loading ? (
                <div style={styles.loading}>Checking keys...</div>
              ) : (
                <>
                  <div style={styles.infoRow}>
                    <span style={styles.infoLabel}>Private Key:</span>
                    {hasPrivateKey ? (
                      <span style={styles.statusBadgeSuccess}>
                        ✅ Stored Locally
                      </span>
                    ) : (
                      <span style={styles.statusBadgeWarning}>
                        ⚠️ Not Found
                      </span>
                    )}
                  </div>
                  {keyInfo && (
                    <>
                      <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>Algorithm:</span>
                        <span style={styles.infoValue}>{keyInfo.algorithm}</span>
                      </div>
                      <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>Key Type:</span>
                        <span style={styles.infoValue}>{keyInfo.keyType}</span>
                      </div>
                      <div style={styles.infoRow}>
                        <span style={styles.infoLabel}>Key Size:</span>
                        <span style={styles.infoValue}>{keyInfo.keySize}</span>
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Security Information Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>🔒</span>
              <h3 style={styles.cardTitle}>Security Information</h3>
            </div>
            <div style={styles.cardBody}>
              <div style={styles.securityList}>
                <div style={styles.securityItem}>
                  <span style={styles.securityIcon}>✓</span>
                  <span style={styles.securityText}>
                    Private key stored in browser's IndexedDB
                  </span>
                </div>
                <div style={styles.securityItem}>
                  <span style={styles.securityIcon}>✓</span>
                  <span style={styles.securityText}>
                    Private keys never transmitted to server
                  </span>
                </div>
                <div style={styles.securityItem}>
                  <span style={styles.securityIcon}>✓</span>
                  <span style={styles.securityText}>
                    Only public key stored on server
                  </span>
                </div>
                <div style={styles.securityItem}>
                  <span style={styles.securityIcon}>✓</span>
                  <span style={styles.securityText}>
                    End-to-end encryption ready
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* System Status Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>⚙️</span>
              <h3 style={styles.cardTitle}>System Status</h3>
            </div>
            <div style={styles.cardBody}>
              <div style={styles.statusGrid}>
                <div style={styles.statusItem}>
                  <div style={styles.statusIndicator}></div>
                  <span style={styles.statusText}>Authentication</span>
                </div>
                <div style={styles.statusItem}>
                  <div style={styles.statusIndicator}></div>
                  <span style={styles.statusText}>Key Management</span>
                </div>
                <div style={styles.statusItem}>
                  <div style={styles.statusIndicator}></div>
                  <span style={styles.statusText}>Encryption</span>
                </div>
              </div>
            </div>
          </div>

          {/* Key Exchange Demo Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>🔄</span>
              <h3 style={styles.cardTitle}>Secure Key Exchange Demo (ECDH + Signatures)</h3>
            </div>
            <div style={styles.cardBody}>
              <div style={styles.formRow}>
                <label style={styles.infoLabel}>
                  Peer Username:
                </label>
                <input
                  type="text"
                  value={peerUsername}
                  onChange={(e) => setPeerUsername(e.target.value)}
                  placeholder="Enter peer username (e.g., user2)"
                  style={styles.textInput}
                />
              </div>
              <div style={{ marginTop: '12px', display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  onClick={handleStartKeyExchange}
                  style={styles.primaryButton}
                >
                  Start Key Exchange (Initiator)
                </button>
                <button
                  type="button"
                  onClick={handleCheckInbox}
                  style={styles.secondaryButton}
                >
                  Check Inbox / Process Messages
                </button>
              </div>
              <div style={{ marginTop: '16px' }}>
                <div style={styles.infoLabel}>Protocol Status:</div>
                <div style={styles.logBox}>
                  {kxLog.length === 0 ? (
                    <div style={styles.logLine}>
                      No key exchange activity yet. Use the buttons above to start.
                    </div>
                  ) : (
                    kxLog.map((line, idx) => (
                      <div key={idx} style={styles.logLine}>
                        {line}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Encrypted Chat Demo Card */}
          <div style={styles.card} className="dashboard-card">
            <div style={styles.cardHeader}>
              <span style={styles.cardIcon}>💬</span>
              <h3 style={styles.cardTitle}>End-to-End Encrypted Chat (AES-256-GCM)</h3>
            </div>
            <div style={styles.cardBody}>
              {!canChat ? (
                <div style={styles.loading}>
                  Establish a secure session with key exchange first, then you can send encrypted
                  messages.
                </div>
              ) : (
                <>
                  <div style={styles.infoRow}>
                    <span style={styles.infoLabel}>Chatting with:</span>
                    <span style={styles.infoValue}>{kxContext.peer}</span>
                  </div>
                  <div style={styles.chatBox}>
                    {chatMessages.length === 0 ? (
                      <div style={styles.chatEmpty}>No messages yet.</div>
                    ) : (
                      chatMessages.map((m, idx) => (
                        <div
                          key={idx}
                          style={
                            m.from === username ? styles.chatBubbleMe : styles.chatBubblePeer
                          }
                        >
                          <div style={styles.chatMeta}>
                            <span>{m.from}</span>
                            <span>
                              {m.timestamp instanceof Date
                                ? m.timestamp.toLocaleTimeString()
                                : ''}
                            </span>
                          </div>
                          <div style={styles.chatText}>{m.content}</div>
                        </div>
                      ))
                    )}
                  </div>
                  <div style={{ marginTop: '10px' }}>
                    <textarea
                      rows={2}
                      style={styles.chatInput}
                      placeholder="Type encrypted message..."
                      value={newMessage}
                      onChange={(e) => setNewMessage(e.target.value)}
                    />
                    <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                      <button
                        type="button"
                        onClick={handleSendMessage}
                        style={styles.primaryButton}
                        disabled={!newMessage.trim()}
                      >
                        Send Encrypted Message
                      </button>
                      <button
                        type="button"
                        onClick={handleLoadMessages}
                        style={styles.secondaryButton}
                      >
                        Refresh Messages
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#f8f9fa',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
  },
  header: {
    backgroundColor: '#ffffff',
    borderBottom: '1px solid #e9ecef',
    padding: '20px 0',
    boxShadow: '0 2px 4px rgba(0,0,0,0.05)'
  },
  headerContent: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '0 20px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  headerTitle: {
    fontSize: '24px',
    fontWeight: '600',
    color: '#212529',
    margin: 0
  },
  logoutButton: {
    padding: '10px 20px',
    backgroundColor: '#dc3545',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
    transition: 'all 0.2s ease',
  },
  content: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '30px 20px'
  },
  welcomeCard: {
    backgroundColor: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    borderRadius: '12px',
    padding: '40px',
    marginBottom: '30px',
    textAlign: 'center',
    color: 'white',
    boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
  },
  welcomeIcon: {
    fontSize: '48px',
    marginBottom: '10px'
  },
  welcomeTitle: {
    fontSize: '28px',
    fontWeight: '600',
    margin: '10px 0',
    color: 'white'
  },
  welcomeSubtitle: {
    fontSize: '16px',
    opacity: 0.9,
    margin: 0
  },
  cardsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '20px'
  },
  card: {
    backgroundColor: '#ffffff',
    borderRadius: '12px',
    padding: '24px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.08)',
    transition: 'transform 0.2s ease, box-shadow 0.2s ease',
    border: '1px solid #e9ecef'
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: '20px',
    paddingBottom: '16px',
    borderBottom: '2px solid #f8f9fa'
  },
  cardIcon: {
    fontSize: '24px',
    marginRight: '12px'
  },
  cardTitle: {
    fontSize: '18px',
    fontWeight: '600',
    color: '#212529',
    margin: 0
  },
  cardBody: {
    color: '#495057'
  },
  infoRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 0',
    borderBottom: '1px solid #f8f9fa'
  },
  infoRowLast: {
    borderBottom: 'none'
  },
  infoLabel: {
    fontSize: '14px',
    color: '#6c757d',
    fontWeight: '500'
  },
  infoValue: {
    fontSize: '14px',
    color: '#212529',
    fontWeight: '600'
  },
  statusBadge: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '600',
    backgroundColor: '#e7f3ff',
    color: '#0066cc'
  },
  statusBadgeSuccess: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '600',
    backgroundColor: '#d4edda',
    color: '#155724'
  },
  statusBadgeWarning: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '600',
    backgroundColor: '#fff3cd',
    color: '#856404'
  },
  securityList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  securityItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '12px'
  },
  securityIcon: {
    color: '#28a745',
    fontWeight: 'bold',
    fontSize: '16px',
    marginTop: '2px'
  },
  securityText: {
    fontSize: '14px',
    color: '#495057',
    lineHeight: '1.5'
  },
  statusGrid: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  statusItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px'
  },
  statusIndicator: {
    width: '12px',
    height: '12px',
    borderRadius: '50%',
    backgroundColor: '#28a745',
    boxShadow: '0 0 0 3px rgba(40, 167, 69, 0.2)'
  },
  statusText: {
    fontSize: '14px',
    color: '#495057',
    fontWeight: '500'
  },
  loading: {
    textAlign: 'center',
    padding: '20px',
    color: '#6c757d',
    fontSize: '14px'
  },
  formRow: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px'
  },
  textInput: {
    width: '100%',
    padding: '8px 10px',
    borderRadius: '4px',
    border: '1px solid #ced4da',
    fontSize: '14px',
    boxSizing: 'border-box'
  },
  primaryButton: {
    padding: '8px 14px',
    backgroundColor: '#007bff',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '14px',
    cursor: 'pointer'
  },
  secondaryButton: {
    padding: '8px 14px',
    backgroundColor: '#6c757d',
    color: '#fff',
    border: 'none',
    borderRadius: '4px',
    fontSize: '14px',
    cursor: 'pointer'
  },
  logBox: {
    marginTop: '8px',
    maxHeight: '160px',
    overflowY: 'auto',
    borderRadius: '4px',
    border: '1px solid #e9ecef',
    padding: '8px',
    backgroundColor: '#fdfdfe'
  },
  logLine: {
    fontSize: '12px',
    color: '#495057',
    marginBottom: '4px'
  },
  chatBox: {
    marginTop: '10px',
    maxHeight: '200px',
    overflowY: 'auto',
    border: '1px solid #e9ecef',
    borderRadius: '6px',
    padding: '8px',
    backgroundColor: '#f8f9fa',
    display: 'flex',
    flexDirection: 'column',
    gap: '6px'
  },
  chatEmpty: {
    fontSize: '13px',
    color: '#6c757d'
  },
  chatBubbleMe: {
    alignSelf: 'flex-end',
    backgroundColor: '#007bff',
    color: '#fff',
    padding: '6px 10px',
    borderRadius: '10px',
    maxWidth: '80%',
    fontSize: '13px'
  },
  chatBubblePeer: {
    alignSelf: 'flex-start',
    backgroundColor: '#e9ecef',
    color: '#212529',
    padding: '6px 10px',
    borderRadius: '10px',
    maxWidth: '80%',
    fontSize: '13px'
  },
  chatMeta: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '11px',
    marginBottom: '2px',
    opacity: 0.8
  },
  chatText: {
    fontSize: '13px',
    wordBreak: 'break-word'
  },
  chatInput: {
    width: '100%',
    padding: '8px 10px',
    borderRadius: '4px',
    border: '1px solid #ced4da',
    resize: 'vertical',
    fontSize: '14px',
    boxSizing: 'border-box'
  }
};

export default Dashboard;

