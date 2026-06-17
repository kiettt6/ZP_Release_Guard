// ZLP ReleaseGuard — chat web client.
// Talks to POST /chat, backed by the ReleaseGuard chat engine.

(() => {
  const STORAGE = {
    chatId: 'zp_release_guard_chat_id',
    messages: 'zp_release_guard_messages',
    theme: 'zp_release_guard_theme',
    outputLanguage: 'zp_release_guard_output_language',
  };

  // "+" menu labels: tag the request so the assistant knows what to do. `directive` is
  // prepended to the sent message (not shown to the user); `chip` shows in the composer.
  const LABELS = {
    impact:   { chip: '📋 Impact Analysis', directive: 'Yêu cầu: phân tích Impact Analysis (tác động & rủi ro QA) cho nội dung sau.' },
    diff:     { chip: '🔀 Review Git diff',  directive: 'Yêu cầu: review Git diff sau, soi rủi ro QA và điểm cần chú ý.' },
    prd:      { chip: '📄 Review PRD',        directive: 'Yêu cầu: review PRD sau, đánh giá rủi ro và acceptance criteria.' },
    release:  { chip: '📝 Release Note',      directive: 'Yêu cầu: review release note sau và đánh giá rủi ro phát hành.' },
    bugfix:   { chip: '🐞 Bug fix / RCA',     directive: 'Yêu cầu: phân tích bug fix / RCA sau, soi nguyên nhân và rủi ro hồi quy.' },
    security: { chip: '🔒 Security review',   directive: 'Yêu cầu: tập trung review BẢO MẬT cho thay đổi sau (auth, token, PII, fraud, OWASP).' },
    p0:       { chip: '✅ P0 smoke checklist', directive: 'Yêu cầu: tạo P0 smoke checklist cụ thể cho thay đổi sau.' },
  };

  const $ = (sel) => document.querySelector(sel);

  const messagesEl = $('#messages');
  const inputEl = $('#input');
  const composerEl = $('#composer');
  const sendBtn = $('#send-btn');
  const charCountEl = $('#char-count');
  const newChatBtn = $('#new-chat-btn');
  const themeToggleBtn = $('#theme-toggle');
  const sidebarToggleBtn = $('#sidebar-toggle');
  const sidebarEl = $('#sidebar');
  const backdropEl = $('#sidebar-backdrop');
  const connStatusEl = $('#connection-status');
  const plusBtn = $('#plus-btn');
  const plusMenu = $('#plus-menu');
  const attachBtn = $('#attach-btn');
  const labelBar = $('#label-bar');
  const labelChip = $('#label-chip');
  const labelCancel = $('#label-cancel');
  const fileInputEl = $('#file-input');
  const attachmentBar = $('#attachment-bar');
  const outputLanguageEl = $('#output-language');
  const scrollBottomBtn = $('#scroll-bottom-btn');
  const replyBar = $('#reply-bar');
  const replySnippetEl = $('#reply-snippet');
  const replyCancelBtn = $('#reply-cancel');
  const newChatModal = $('#new-chat-modal');
  const newChatCancelBtn = $('#new-chat-cancel');
  const newChatConfirmBtn = $('#new-chat-confirm');

  const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
  const MAX_TOTAL_UPLOAD_BYTES = 20 * 1024 * 1024;
  const MAX_UPLOAD_FILES = 5;
  const ALLOWED_EXT = new Set([
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic',
    'pdf', 'docx',
    'txt', 'md', 'json', 'py', 'diff', 'patch', 'yml', 'yaml', 'ini', 'log', 'csv', 'tsv',
  ]);

  // --- State ---
  let chatId = loadChatId();
  let history = loadHistory();
  let inFlight = false;
  let pendingFiles = [];      // { file, previewURL } selected but not yet sent
  let replyingTo = null;      // assistant message text the user is replying to
  let activeLabel = null;     // request label key from the "+" menu

  // --- Init ---
  applyTheme(localStorage.getItem(STORAGE.theme) || preferredTheme());
  applyOutputLanguage(localStorage.getItem(STORAGE.outputLanguage) || 'default');

  if (history.length === 0) {
    renderWelcome();
  } else {
    history.forEach(m => renderMessage(m, /*animate*/ false));
  }
  scrollToBottom(false);
  updateCharCount();
  updateSendButton();

  // --- Event wiring ---
  composerEl.addEventListener('submit', (e) => {
    e.preventDefault();
    submitMessage();
  });

  // Show a scroll-to-bottom button when the user has scrolled up in a long thread.
  const messagesWrapper = document.querySelector('.messages-wrapper');
  const updateScrollBtn = () => {
    const distance = messagesWrapper.scrollHeight - messagesWrapper.scrollTop - messagesWrapper.clientHeight;
    scrollBottomBtn.hidden = distance < 120;
  };
  messagesWrapper.addEventListener('scroll', updateScrollBtn, { passive: true });
  scrollBottomBtn.addEventListener('click', () => { scrollToBottom(); scrollBottomBtn.hidden = true; });

  replyCancelBtn.addEventListener('click', clearReply);

  function startReply(text) {
    replyingTo = (text || '').trim();
    if (!replyingTo) return;
    const oneLine = replyingTo.replace(/\s+/g, ' ');
    replySnippetEl.textContent = oneLine.length > 120 ? oneLine.slice(0, 120) + '…' : oneLine;
    replyBar.hidden = false;
    inputEl.focus();
  }

  function clearReply() {
    replyingTo = null;
    replySnippetEl.textContent = '';
    replyBar.hidden = true;
  }

  inputEl.addEventListener('input', () => {
    autoGrow();
    updateCharCount();
    updateSendButton();
  });

  inputEl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      submitMessage();
    }
  });

  newChatBtn.addEventListener('click', () => {
    if (history.length === 0) return;
    openNewChatModal();
  });

  newChatCancelBtn.addEventListener('click', closeNewChatModal);
  newChatConfirmBtn.addEventListener('click', () => {
    closeNewChatModal();
    resetConversation();
  });
  newChatModal.addEventListener('click', (e) => {
    if (e.target === newChatModal) closeNewChatModal();
  });

  themeToggleBtn.addEventListener('click', () => {
    const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(next);
  });

  outputLanguageEl.addEventListener('change', () => {
    applyOutputLanguage(outputLanguageEl.value);
  });

  sidebarToggleBtn.addEventListener('click', () => {
    sidebarEl.classList.toggle('open');
    backdropEl.classList.toggle('active');
  });
  backdropEl.addEventListener('click', () => {
    sidebarEl.classList.remove('open');
    backdropEl.classList.remove('active');
  });

  document.querySelectorAll('.sample-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.sample;
      if (!name || inFlight) return;
      sidebarEl.classList.remove('open');
      backdropEl.classList.remove('active');
      sendRaw(`/sample ${name}`, /*displayLabel*/ sampleLabel(name));
    });
  });

  // "+" menu: pick a request label so the assistant knows what to do.
  function togglePlusMenu(open) {
    const show = open === undefined ? plusMenu.hidden : open;
    plusMenu.hidden = !show;
    plusBtn.setAttribute('aria-expanded', String(show));
  }
  plusBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    togglePlusMenu();
  });
  document.addEventListener('click', (e) => {
    if (!plusMenu.hidden && !plusMenu.contains(e.target) && e.target !== plusBtn) togglePlusMenu(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !newChatModal.hidden) {
      closeNewChatModal();
      return;
    }
    if (e.key === 'Escape' && !plusMenu.hidden) togglePlusMenu(false);
  });
  plusMenu.addEventListener('click', (e) => {
    const item = e.target.closest('.plus-item');
    if (!item) return;
    togglePlusMenu(false);
    setActiveLabel(item.dataset.label);
  });

  function setActiveLabel(key) {
    if (!LABELS[key]) return;
    activeLabel = key;
    labelChip.textContent = LABELS[key].chip;
    labelBar.hidden = false;
    inputEl.focus();
  }
  function clearActiveLabel() {
    activeLabel = null;
    labelChip.textContent = '';
    labelBar.hidden = true;
  }
  labelCancel.addEventListener('click', clearActiveLabel);

  // Separate file-attachment button (paperclip)
  attachBtn.addEventListener('click', () => {
    if (inFlight) return;
    fileInputEl.click();
  });

  fileInputEl.addEventListener('change', () => {
    const files = Array.from(fileInputEl.files || []);
    fileInputEl.value = '';  // allow same-file re-pick
    if (files.length) selectFiles(files);
  });

  // Drag & drop onto the composer area
  ['dragenter', 'dragover'].forEach(ev => composerEl.addEventListener(ev, (e) => {
    e.preventDefault();
    composerEl.classList.add('drag-over');
  }));
  ['dragleave', 'drop'].forEach(ev => composerEl.addEventListener(ev, (e) => {
    e.preventDefault();
    composerEl.classList.remove('drag-over');
  }));
  composerEl.addEventListener('drop', (e) => {
    if (inFlight) return;
    const files = Array.from(e.dataTransfer.files || []);
    if (files.length) selectFiles(files);
  });

  // Paste image(s) from clipboard
  inputEl.addEventListener('paste', (e) => {
    if (inFlight) return;
    const items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    const files = [];
    for (const it of items) {
      if (it.kind === 'file') {
        const f = it.getAsFile();
        if (f) files.push(f);
      }
    }
    if (files.length) {
      selectFiles(files);
      e.preventDefault();
    }
  });

  // --- Functions ---

  function preferredTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    document.body.dataset.theme = theme;
    localStorage.setItem(STORAGE.theme, theme);
  }

  function applyOutputLanguage(language) {
    const allowed = new Set(['default', 'English', 'Vietnamese']);
    const next = allowed.has(language) ? language : 'default';
    outputLanguageEl.value = next;
    localStorage.setItem(STORAGE.outputLanguage, next);
  }

  function selectedOutputLanguage() {
    return outputLanguageEl.value || 'default';
  }

  function loadChatId() {
    const raw = localStorage.getItem(STORAGE.chatId);
    if (raw && /^\d+$/.test(raw)) return Number(raw);
    return null;
  }

  function saveChatId(id) {
    if (id) localStorage.setItem(STORAGE.chatId, String(id));
  }

  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE.messages);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  }

  function saveHistory() {
    try {
      // Cap stored history at the last 30 messages to keep localStorage healthy.
      // Strip ephemeral blob URLs — they're invalid after reload anyway.
      const tail = history.slice(-30).map(m => {
        if (m.attachments) {
          return {
            ...m,
            attachments: m.attachments.map(({ previewURL, ...rest }) => rest),
          };
        }
        if (m.attachment) {
          const { previewURL, ...rest } = m.attachment;
          return { ...m, attachment: rest };
        }
        return m;
      });
      localStorage.setItem(STORAGE.messages, JSON.stringify(tail));
    } catch { /* quota — ignore */ }
  }

  function openNewChatModal() {
    newChatModal.hidden = false;
    newChatCancelBtn.focus();
  }

  function closeNewChatModal() {
    newChatModal.hidden = true;
    newChatBtn.focus();
  }

  function resetConversation() {
    chatId = null;
    history = [];
    localStorage.removeItem(STORAGE.chatId);
    localStorage.removeItem(STORAGE.messages);
    clearPendingFiles();
    messagesEl.innerHTML = '';
    renderWelcome();
    inputEl.value = '';
    autoGrow();
    updateCharCount();
    updateSendButton();
    inputEl.focus();
  }

  function autoGrow() {
    inputEl.style.height = 'auto';
    inputEl.style.height = Math.min(inputEl.scrollHeight, 220) + 'px';
  }

  function updateCharCount() {
    const len = inputEl.value.length;
    charCountEl.textContent = len > 0 ? len.toLocaleString() : '';
    charCountEl.classList.toggle('warn', len > 40000 && len <= 50000);
    charCountEl.classList.toggle('over', len > 50000);
  }

  function updateSendButton() {
    const text = inputEl.value.trim();
    const hasFile = pendingFiles.length > 0;
    // With files you can send without text; without files you need text.
    sendBtn.disabled = inFlight || (text.length === 0 && !hasFile) || text.length > 50000;
    plusBtn.disabled = inFlight;
    attachBtn.disabled = inFlight;
  }

  function fileExt(name) {
    if (!name || !name.includes('.')) return '';
    return name.split('.').pop().toLowerCase();
  }

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function fileKindFor(file) {
    const ext = fileExt(file.name);
    if ((file.type || '').startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic'].includes(ext)) return 'image';
    if (file.type === 'application/pdf' || ext === 'pdf') return 'pdf';
    if (ext === 'docx' || (file.type || '').includes('wordprocessingml')) return 'docx';
    return 'text';
  }

  function validateUploadFile(file) {
    if (file.size > MAX_UPLOAD_BYTES) {
      alert(`File quá lớn (${formatBytes(file.size)}). Tối đa 10MB.`);
      return false;
    }
    const ext = fileExt(file.name);
    const okType = (file.type || '').startsWith('image/') || ALLOWED_EXT.has(ext);
    if (!okType) {
      alert(`Định dạng không hỗ trợ: .${ext || '?'}. Cho phép: ảnh, PDF, DOCX, hoặc text.`);
      return false;
    }
    return true;
  }

  function selectFiles(files) {
    const incoming = Array.from(files || []).filter(Boolean);
    if (!incoming.length) return;
    const slots = MAX_UPLOAD_FILES - pendingFiles.length;
    if (slots <= 0) {
      alert(`Chỉ hỗ trợ tối đa ${MAX_UPLOAD_FILES} file mỗi lần gửi.`);
      return;
    }
    let totalBytes = pendingFiles.reduce((sum, item) => sum + item.file.size, 0);
    const accepted = [];
    for (const file of incoming.slice(0, slots)) {
      if (!validateUploadFile(file)) continue;
      if (totalBytes + file.size > MAX_TOTAL_UPLOAD_BYTES) {
        alert(`Tổng dung lượng file quá lớn. Tối đa ${formatBytes(MAX_TOTAL_UPLOAD_BYTES)} mỗi lần gửi.`);
        break;
      }
      totalBytes += file.size;
      accepted.push({
        file,
        previewURL: fileKindFor(file) === 'image' ? URL.createObjectURL(file) : null,
      });
    }
    if (incoming.length > slots) {
      alert(`Chỉ thêm ${slots} file. Tối đa ${MAX_UPLOAD_FILES} file mỗi lần gửi.`);
    }
    pendingFiles.push(...accepted);
    renderAttachmentPills();
    updateSendButton();
    inputEl.focus();
  }

  function clearPendingFiles() {
    pendingFiles.forEach(item => {
      if (item.previewURL) URL.revokeObjectURL(item.previewURL);
    });
    pendingFiles = [];
    attachmentBar.innerHTML = '';
    attachmentBar.hidden = true;
  }

  function removePendingFile(index) {
    const [removed] = pendingFiles.splice(index, 1);
    if (removed && removed.previewURL) URL.revokeObjectURL(removed.previewURL);
    renderAttachmentPills();
    updateSendButton();
  }

  function renderAttachmentPills(opts = {}) {
    attachmentBar.innerHTML = '';
    pendingFiles.forEach((item, index) => {
      attachmentBar.appendChild(buildAttachmentPill(item.file, item.previewURL, {
        ...opts,
        index,
      }));
    });
    attachmentBar.hidden = pendingFiles.length === 0;
  }

  function buildAttachmentPill(file, previewURL, opts = {}) {
    const pill = document.createElement('div');
    pill.className = 'attachment-pill' + (opts.uploading ? ' uploading' : '');

    const thumb = document.createElement('div');
    thumb.className = 'attachment-thumb';
    const kind = fileKindFor(file);
    if (kind === 'image' && previewURL) {
      const img = document.createElement('img');
      img.alt = file.name;
      img.onerror = () => { thumb.innerHTML = kindIcon('image'); };
      img.src = previewURL;
      thumb.appendChild(img);
    } else {
      thumb.innerHTML = kindIcon(kind);
    }
    pill.appendChild(thumb);

    const info = document.createElement('div');
    info.className = 'attachment-info';
    const name = document.createElement('div');
    name.className = 'attachment-name';
    name.textContent = file.name;
    name.title = file.name;
    const meta = document.createElement('div');
    meta.className = 'attachment-meta';
    meta.textContent = `${kind.toUpperCase()} · ${formatBytes(file.size)}` + (opts.uploading ? ' · đang tải lên…' : '');
    info.appendChild(name);
    info.appendChild(meta);
    pill.appendChild(info);

    if (!opts.uploading) {
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'attachment-remove';
      remove.title = 'Bỏ file';
      remove.setAttribute('aria-label', 'Bỏ file');
      remove.innerHTML = `
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>`;
      remove.addEventListener('click', () => {
        removePendingFile(opts.index);
      });
      pill.appendChild(remove);
    }

    return pill;
  }

  function kindIcon(kind) {
    const common = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
    if (kind === 'pdf') return `<svg ${common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><text x="6" y="17" font-size="6" font-family="sans-serif" stroke="none" fill="currentColor" font-weight="700">PDF</text></svg>`;
    if (kind === 'docx') return `<svg ${common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><text x="5" y="17" font-size="5" font-family="sans-serif" stroke="none" fill="currentColor" font-weight="700">DOC</text></svg>`;
    if (kind === 'image') return `<svg ${common}><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`;
    return `<svg ${common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="14" y2="17"/></svg>`;
  }

  function setBusy(busy) {
    inFlight = busy;
    updateSendButton();
    connStatusEl.classList.toggle('busy', busy);
    connStatusEl.querySelector('.dot').nextSibling.textContent =
      busy ? ' Đang phân tích…' : ' Sẵn sàng';
  }

  function setError(text) {
    connStatusEl.classList.add('error');
    connStatusEl.classList.remove('busy');
    connStatusEl.querySelector('.dot').nextSibling.textContent = ' ' + text;
  }

  function clearError() {
    connStatusEl.classList.remove('error');
  }

  function sampleLabel(name) {
    switch (name) {
      case 'refund': return 'Phân tích mẫu: Refund flow';
      case 'promo': return 'Phân tích mẫu: Promotion / Cashback';
      case 'banklink': return 'Phân tích mẫu: Bank linking';
      default: return `/sample ${name}`;
    }
  }

  function submitMessage() {
    const text = inputEl.value.trim();
    if (inFlight) return;
    if (!text && pendingFiles.length === 0) return;

    // Consume the active request label: prepend its directive to what the server
    // sees, show its chip on the user message, then clear it.
    const label = activeLabel;
    const directive = label ? LABELS[label].directive : '';
    const chip = label ? LABELS[label].chip : null;
    clearActiveLabel();

    if (pendingFiles.length > 0) {
      const files = pendingFiles;
      pendingFiles = [];
      attachmentBar.innerHTML = '';
      attachmentBar.hidden = true;
      inputEl.value = '';
      autoGrow();
      updateCharCount();
      sendWithFiles(text, files, directive, chip);
    } else {
      inputEl.value = '';
      autoGrow();
      updateCharCount();
      const serverText = directive ? `${directive}\n\n${text}` : text;
      sendRaw(serverText, text, chip);
    }
  }

  function askFollowup(question) {
    if (inFlight) return;
    clearError();
    inputEl.value = '';
    autoGrow();
    updateCharCount();
    sendRaw(question);
  }

  function followupSuggestions(msg) {
    const vi = msg.language !== 'English';
    if (msg.kind === 'report') {
      const risk = msg.risk_level || (vi ? 'này' : 'this');
      return vi
        ? [`Vì sao mức rủi ro là ${risk}?`, 'Nên test gì trước tiên?', 'Giải thích finding nghiêm trọng nhất', 'Cần hỏi dev những gì?']
        : [`Why is the risk ${risk}?`, 'What should I test first?', 'Explain the most severe finding', 'What should I ask the devs?'];
    }
    // File-analysis chat replies (uploaded doc/image)
    if (msg.extracted_text) {
      return vi
        ? ['Tóm tắt ngắn gọn giúp tôi', 'Rủi ro nào nghiêm trọng nhất?', 'Đề xuất test case P0', 'Cần hỏi dev những gì?']
        : ['Give me a short summary', 'Which risk is most severe?', 'Suggest P0 test cases', 'What should I ask the devs?'];
    }
    return [];
  }

  function buildFollowups(msg) {
    const items = followupSuggestions(msg);
    if (!items.length) return null;
    const wrap = document.createElement('div');
    wrap.className = 'followups';
    const label = document.createElement('span');
    label.className = 'followups-label';
    label.textContent = (msg.language === 'English') ? 'Gợi ý:' : 'Hỏi tiếp:';
    wrap.appendChild(label);
    items.forEach((q) => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'followup-chip';
      chip.textContent = q;
      chip.addEventListener('click', () => askFollowup(q));
      wrap.appendChild(chip);
    });
    return wrap;
  }

  async function sendRaw(serverText, displayText, labelChip) {
    clearWelcome();
    clearError();

    // Snapshot + consume the reply context for this turn.
    const repliedTo = replyingTo;
    clearReply();

    const userMsg = {
      role: 'user',
      content: displayText || serverText,
      ts: Date.now(),
      replyQuote: repliedTo || null,
      label: labelChip || null,
    };
    history.push(userMsg);
    renderMessage(userMsg);
    saveHistory();
    scrollToBottom();

    const typingEl = renderTyping();
    setBusy(true);

    try {
      const res = await fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: serverText,
          chat_id: chatId || undefined,
          replied_assistant_message: repliedTo ? repliedTo.slice(0, 4000) : undefined,
          output_language: selectedOutputLanguage(),
        }),
      });

      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      handleAssistantResponse(data, typingEl);
    } catch (err) {
      typingEl.remove();
      renderError(err, () => sendRaw(serverText, displayText, labelChip));
    } finally {
      setBusy(false);
      inputEl.focus();
    }
  }

  async function sendWithFiles(text, files, directive, labelChip) {
    clearWelcome();
    clearError();

    const attachments = files.map(item => ({
      name: item.file.name,
      kind: fileKindFor(item.file),
      size: item.file.size,
      previewURL: item.previewURL,  // ephemeral — not persisted
    }));

    const userMsg = {
      role: 'user',
      content: text || '',
      ts: Date.now(),
      label: labelChip || null,
      attachments,
    };
    history.push(userMsg);
    renderMessage(userMsg);
    // Persist a stripped copy (no preview URL / blob)
    saveHistory();
    scrollToBottom();

    const typingEl = renderTyping();
    setBusy(true);

    try {
      const fd = new FormData();
      files.forEach(item => fd.append('files', item.file));
      // Prepend the request-label directive (if any) so the assistant knows the task.
      const msgField = directive ? (text ? `${directive}\n\n${text}` : directive) : (text || '');
      fd.append('message', msgField);
      if (chatId) fd.append('chat_id', String(chatId));
      fd.append('output_language', selectedOutputLanguage());

      const res = await fetch('/chat-upload', { method: 'POST', body: fd });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      handleAssistantResponse(data, typingEl);
    } catch (err) {
      typingEl.remove();
      renderError(err, () => sendWithFiles(text, files, directive, labelChip));
    } finally {
      setBusy(false);
      inputEl.focus();
    }
  }

  function handleAssistantResponse(data, typingEl) {
    if (data.chat_id && !chatId) {
      chatId = data.chat_id;
      saveChatId(chatId);
    }
    const assistantMsg = {
      role: 'assistant',
      content: data.reply,
      kind: data.kind,
      risk_level: data.risk_level,
      recommendation: data.recommendation,
      language: data.language,
      extracted_text: data.extracted_text || null,
      extracted_chars: data.extracted_chars || null,
      file_name: data.file_name || null,
      file_kind: data.file_kind || null,
      file_count: data.file_count || null,
      file_names: data.file_names || null,
      ts: Date.now(),
    };
    history.push(assistantMsg);
    saveHistory();
    typingEl.remove();
    renderMessage(assistantMsg);
    scrollToBottom();
  }

  function renderError(err, retryFn) {
    const errMsg = {
      role: 'assistant',
      content: 'Không thể xử lý yêu cầu: ' + (err && err.message ? err.message : 'unknown error'),
      kind: 'error',
      retryFn: retryFn || null,
      ts: Date.now(),
    };
    renderMessage(errMsg);
    setError('Lỗi kết nối');
  }

  function sendFeedback(rating) {
    // Fire-and-forget; never block the UI on feedback.
    try {
      fetch('/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rating, chat_id: chatId || undefined }),
      }).catch(() => { });
    } catch { /* ignore */ }
  }

  // --- Rendering ---

  function renderWelcome() {
    const el = document.createElement('div');
    el.className = 'welcome';
    el.id = 'welcome';
    el.innerHTML = `
      <div class="welcome-logo">
        <img src="/zalopay.png" alt="ZaloPay" width="132" height="98">
      </div>
      <h2>Xin chào — bắt đầu review release</h2>
      <p>Tôi là <strong>ZLP ReleaseGuard</strong>, trợ lý QA phân tích rủi ro release cho toàn bộ luồng ZaloPay. Paste impact analysis, Git diff, PRD hoặc release note để được phân tích, hoặc hỏi follow-up bằng tiếng Việt / English.</p>
      <div class="welcome-suggestions">
        <button class="welcome-suggestion" data-prompt="Refund retry flow with partner timeout — fix race condition causing double refund credits when Napas callback retries after 30s.">
          <strong>💸 Refund retry flow</strong>
          <span>Risk: double refund khi partner timeout</span>
        </button>
        <button class="welcome-suggestion" data-prompt="Release Notes v2.8.1 cashback campaign for merchant QR payments — auto-grant 5% cashback on first transaction, cap 200k VND/user.">
          <strong>🎁 Cashback campaign</strong>
          <span>Promo · cap per user · grant idempotency</span>
        </button>
        <button class="welcome-suggestion" data-prompt="Migration: thêm column status_v2 vào bảng wallet_balance (NOT NULL default 'active'). Rollback plan chưa có. Backfill chạy trong giờ peak.">
          <strong>🗃 Schema migration</strong>
          <span>NOT NULL · backfill · rollback gap</span>
        </button>
        <button class="welcome-suggestion" data-prompt="Bug fix: PIN reset OTP gửi không giới hạn — thêm rate limit 3 lần / 5 phút / user. Áp dụng cho cả Smart OTP và SMS OTP.">
          <strong>🔐 PIN reset rate limit</strong>
          <span>OTP · UM · anti-abuse</span>
        </button>
      </div>
    `;
    messagesEl.appendChild(el);
    el.querySelectorAll('.welcome-suggestion').forEach((btn) => {
      btn.addEventListener('click', () => {
        const prompt = btn.dataset.prompt;
        if (prompt) {
          inputEl.value = prompt;
          autoGrow();
          updateCharCount();
          updateSendButton();
          inputEl.focus();
        }
      });
    });
  }

  function clearWelcome() {
    const el = document.getElementById('welcome');
    if (el) el.remove();
  }

  function renderMessage(msg, animate = true) {
    const wrap = document.createElement('div');
    wrap.className = `message ${msg.role}`;
    if (!animate) wrap.style.animation = 'none';

    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    if (msg.role === 'user') {
      avatar.textContent = 'QA';
    } else {
      avatar.innerHTML = `<img src="/zalopay.png" alt="ZaloPay" width="32" height="32">`;
    }

    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    if (msg.kind === 'error') bubble.classList.add('error');

    if (msg.role === 'user') {
      if (msg.label) {
        const lbl = document.createElement('div');
        lbl.className = 'msg-label';
        lbl.textContent = msg.label;
        bubble.appendChild(lbl);
      }
      if (msg.replyQuote) {
        const quote = document.createElement('div');
        quote.className = 'reply-quote';
        const oneLine = msg.replyQuote.replace(/\s+/g, ' ');
        quote.textContent = '↩ ' + (oneLine.length > 100 ? oneLine.slice(0, 100) + '…' : oneLine);
        bubble.appendChild(quote);
      }
      if (msg.attachments && msg.attachments.length) {
        const list = document.createElement('div');
        list.className = 'attachment-inline-list';
        msg.attachments.forEach(att => list.appendChild(buildAttachmentInline(att)));
        bubble.appendChild(list);
      } else if (msg.attachment) {
        bubble.appendChild(buildAttachmentInline(msg.attachment));
      }
      if (msg.content) {
        const textEl = document.createElement('div');
        textEl.textContent = msg.content;
        bubble.appendChild(textEl);
      }
    } else if (msg.kind === 'report') {
      bubble.appendChild(buildReportMeta(msg));
      // Show OCR/extracted text BEFORE the analysis so the user can verify
      // what the assistant actually read from their file — and notice if OCR went wrong.
      if (msg.extracted_text) bubble.appendChild(buildExtractedBlock(msg));
      appendAssistantBody(bubble, msg);
      const disc = document.createElement('div');
      disc.className = 'report-disclaimer';
      disc.textContent = (msg.language === 'English')
        ? '⚠ Automated QA assistant — still requires QA/owner sign-off before release.'
        : '⚠ Phân tích hỗ trợ tự động — vẫn cần QA/owner sign-off trước khi release.';
      bubble.appendChild(disc);
      bubble.appendChild(buildReportActions(msg));
    } else if (msg.kind === 'error') {
      const mdEl = document.createElement('div');
      mdEl.textContent = msg.content;
      bubble.appendChild(mdEl);
      if (msg.retryFn) {
        const retry = document.createElement('div');
        retry.className = 'report-actions';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'report-action-btn';
        btn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
          Thử lại`;
        btn.addEventListener('click', () => { wrap.remove(); msg.retryFn(); });
        retry.appendChild(btn);
        bubble.appendChild(retry);
      }
    } else {
      // chat reply — render as markdown too (LLM may emit lists/bullets)
      if (msg.extracted_text) bubble.appendChild(buildExtractedBlock(msg));
      appendAssistantBody(bubble, msg);
      // Copy/download available on every assistant answer, not only templated reports.
      if (msg.content) bubble.appendChild(buildReportActions(msg));
    }

    wrap.appendChild(avatar);
    wrap.appendChild(bubble);

    // Follow-up suggestion chips live only under the most recent assistant answer.
    messagesEl.querySelectorAll('.followups').forEach((e) => e.remove());
    if (msg.role === 'assistant' && msg.kind !== 'error') {
      const fu = buildFollowups(msg);
      if (fu) bubble.appendChild(fu);
    }

    messagesEl.appendChild(wrap);
  }

  function buildAttachmentInline(att) {
    const wrap = document.createElement('div');
    wrap.className = 'attachment-inline';

    const thumb = document.createElement('div');
    thumb.className = 'attachment-inline-thumb';
    if (att.kind === 'image' && att.previewURL) {
      const img = document.createElement('img');
      img.src = att.previewURL;
      img.alt = att.name || 'attachment';
      thumb.appendChild(img);
    } else {
      thumb.innerHTML = kindIcon(att.kind || 'text');
    }
    wrap.appendChild(thumb);

    const info = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'attachment-inline-name';
    name.textContent = att.name || 'attachment';
    const meta = document.createElement('div');
    meta.className = 'attachment-inline-meta';
    meta.textContent = `${(att.kind || 'file').toUpperCase()}${att.size ? ' · ' + formatBytes(att.size) : ''}`;
    info.appendChild(name);
    info.appendChild(meta);
    wrap.appendChild(info);
    return wrap;
  }

  function buildExtractedBlock(msg) {
    const isImage = msg.file_kind === 'image';
    const isMulti = (msg.file_count || 0) > 1;
    const wrap = document.createElement('div');
    wrap.className = 'extracted-block';

    const header = document.createElement('div');
    header.className = 'extracted-header';
    const icon = isMulti ? '📎' : (isImage ? '📷' : (msg.file_kind === 'pdf' ? '📄' : msg.file_kind === 'docx' ? '📝' : '📃'));
    const kindLabel = isMulti
      ? `Nội dung trích xuất từ ${msg.file_count} file`
      : (isImage ? 'OCR từ ảnh' : `Nội dung trích xuất từ ${(msg.file_kind || 'file').toUpperCase()}`);
    header.innerHTML = `
      <span class="extracted-icon">${icon}</span>
      <span class="extracted-title">${kindLabel}${msg.file_name ? ` · ${escapeHtml(msg.file_name)}` : ''}</span>
      <span class="extracted-count">${(msg.extracted_chars || msg.extracted_text.length).toLocaleString()} ký tự</span>
    `;
    wrap.appendChild(header);

    // Heuristic: if the OCR text looks like the assistant's own self-talk (capability
    // reply or canned greeting), warn the user. This catches the common case of
    // screenshotting a chat with the assistant.
    const looksLikeAssistantEcho = detectAssistantEcho(msg.extracted_text);
    if (looksLikeAssistantEcho) {
      const warn = document.createElement('div');
      warn.className = 'extracted-warning';
      warn.innerHTML = `
        <strong>⚠ Lưu ý:</strong> Nội dung OCR có vẻ là một đoạn chat hoặc mô tả chung,
        không phải tài liệu impact analysis cụ thể. Báo cáo bên dưới được sinh tự động
        từ keyword nên có thể chung chung. Bạn nên paste trực tiếp diff / PRD / impact doc
        để phân tích sát hơn.
      `;
      wrap.appendChild(warn);
    }

    const details = document.createElement('details');
    details.className = 'extracted-text';
    details.open = isImage;  // open by default for images so user can verify OCR
    const summary = document.createElement('summary');
    summary.textContent = details.open ? 'Ẩn nội dung' : 'Xem nội dung';
    details.appendChild(summary);
    details.addEventListener('toggle', () => {
      summary.textContent = details.open ? 'Ẩn nội dung' : 'Xem nội dung';
    });
    const pre = document.createElement('pre');
    pre.textContent = msg.extracted_text;
    details.appendChild(pre);
    wrap.appendChild(details);

    return wrap;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function detectAssistantEcho(text) {
    if (!text) return false;
    const t = text.toLowerCase();
    // Match phrases the assistant itself says — capability reply, canned greeting,
    // sample feature taglines. Lots of false negatives are OK; the signal is
    // when ≥2 distinct fingerprints show up close together.
    const fingerprints = [
      'tôi là zlp releaseguard',
      'tôi là zp releaseguard',
      'i am zlp releaseguard',
      'i am zp releaseguard',
      'trợ lý qa',
      'qa release review assistant',
      'không chỉ riêng payment',
      'not only payment',
      'phân tích rủi ro release cho toàn bộ',
      'send me a release description',
      'vui lòng gửi release description',
    ];
    let hits = 0;
    for (const f of fingerprints) if (t.includes(f)) hits++;
    return hits >= 2;
  }

  function buildReportMeta(msg) {
    const meta = document.createElement('div');
    meta.className = 'report-meta';
    if (msg.risk_level) {
      const pill = document.createElement('span');
      pill.className = 'risk-pill';
      pill.dataset.level = msg.risk_level;
      pill.textContent = `Risk: ${msg.risk_level}`;
      meta.appendChild(pill);
    }
    if (msg.recommendation) {
      const pill = document.createElement('span');
      pill.className = 'rec-pill';
      pill.dataset.rec = msg.recommendation;
      pill.textContent = msg.recommendation;
      meta.appendChild(pill);
    }
    return meta;
  }

  function buildReportActions(msg) {
    const actions = document.createElement('div');
    actions.className = 'report-actions';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'report-action-btn';
    copyBtn.type = 'button';
    copyBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
      </svg>
      Copy`;
    copyBtn.addEventListener('click', async () => {
      const ok = await copyToClipboard(markdownToText(exportableContent(msg)));
      copyBtn.lastChild.textContent = ok ? ' Đã copy' : ' Lỗi copy';
      setTimeout(() => { copyBtn.lastChild.textContent = ' Copy'; }, 1500);
    });
    actions.appendChild(copyBtn);

    const dlBtn = document.createElement('button');
    dlBtn.className = 'report-action-btn';
    dlBtn.type = 'button';
    dlBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      Tải .md`;
    dlBtn.addEventListener('click', () => downloadMarkdown(composeMarkdownDocument(msg)));
    actions.appendChild(dlBtn);

    const replyBtn = document.createElement('button');
    replyBtn.className = 'report-action-btn';
    replyBtn.type = 'button';
    replyBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/>
      </svg>
      Trả lời`;
    replyBtn.addEventListener('click', () => startReply(markdownToText(exportableContent(msg))));
    actions.appendChild(replyBtn);

    // Feedback 👍/👎 — signals quality so rules/knowledge can be improved.
    const fbWrap = document.createElement('span');
    fbWrap.className = 'feedback-group';
    const mkFb = (rating, glyph, title) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'feedback-btn';
      b.title = title;
      b.textContent = glyph;
      b.addEventListener('click', () => {
        fbWrap.querySelectorAll('.feedback-btn').forEach((x) => x.classList.remove('chosen'));
        b.classList.add('chosen');
        sendFeedback(rating);
      });
      return b;
    };
    fbWrap.appendChild(mkFb('up', '👍', 'Hữu ích'));
    fbWrap.appendChild(mkFb('down', '👎', 'Chưa tốt'));
    actions.appendChild(fbWrap);

    return actions;
  }

  function composeMarkdownDocument(msg) {
    // Build a self-contained .md report (metadata + input + extracted file +
    // analysis), not just a dump of the reply text.
    const lines = ['# ZLP ReleaseGuard — QA Analysis', ''];
    const meta = [`Thời điểm: ${new Date().toLocaleString()}`];
    if (msg.risk_level) meta.push(`Risk: ${msg.risk_level}`);
    if (msg.recommendation) meta.push(`Recommendation: ${msg.recommendation}`);
    if (msg.language) meta.push(`Ngôn ngữ: ${msg.language}`);
    lines.push('> ' + meta.join(' · '), '');

    if (msg.extracted_text) {
      const label = msg.file_kind === 'image' ? 'OCR từ ảnh' : `Nội dung trích xuất từ ${(msg.file_kind || 'file').toUpperCase()}`;
      lines.push(`## ${label}${msg.file_name ? ` — ${msg.file_name}` : ''}`, '');
      if (msg.extracted_chars) lines.push(`_${msg.extracted_chars.toLocaleString()} ký tự_`, '');
      lines.push('```', msg.extracted_text, '```', '');
    }

    lines.push('## Phân tích', '', exportableContent(msg), '');
    return lines.join('\n');
  }

  // --- Test cases (rendered as cards + xlsx download) ---

  // Pull a ```testcases fenced JSON block out of an assistant reply.
  // Returns { data, cleaned } where `cleaned` is the reply with the block removed,
  // or null when there is no (valid) block.
  function extractTestCases(content) {
    if (!content || typeof content !== 'string') return null;
    // Normal case: a complete ```testcases ... ``` fenced block.
    let m = content.match(/```testcases\s*([\s\S]*?)```/i);
    let raw = m ? m[1] : null;
    let blockText = m ? m[0] : null;
    // Tolerate a truncated reply (long batch ran out of tokens): an opening fence
    // with no closing one — take everything after it and try to repair the JSON.
    if (!m) {
      const open = content.match(/```testcases\s*([\s\S]*)$/i);
      if (!open) return null;
      raw = open[1];
      blockText = open[0];
    }
    const data = parseTestCaseJson(raw);
    if (!data || !Array.isArray(data.groups) || !data.groups.length) return null;
    const cleaned = content.replace(blockText, '').replace(/\n{3,}/g, '\n\n').trim();
    return { data, cleaned };
  }

  function parseTestCaseJson(raw) {
    const text = String(raw || '').replace(/```[\s\S]*$/, '').trim();  // drop any trailing fence remnant
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch { /* try to repair a truncated reply below */ }
    // A long batch can be cut off mid-case (even mid-key). Retreat to the last
    // complete '}' (end of a finished case/group/object) and close any still-open
    // arrays/objects, so the cases generated before the cutoff still render.
    let cut = text.lastIndexOf('}');
    let attempts = 0;
    while (cut > 0 && attempts < 300) {
      attempts++;
      const closed = _closeOpenBrackets(text.slice(0, cut + 1));
      if (closed) {
        try { return JSON.parse(closed); } catch { /* retreat further */ }
      }
      cut = text.lastIndexOf('}', cut - 1);
    }
    return null;
  }

  // Append the missing closing brackets for a JSON fragment that ends at a '}'.
  function _closeOpenBrackets(s) {
    let inStr = false, esc = false;
    const stack = [];
    for (const ch of s) {
      if (esc) { esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (ch === '{' || ch === '[') stack.push(ch);
      else if (ch === '}' || ch === ']') stack.pop();
    }
    if (inStr) return null;
    let out = s.replace(/,\s*$/, '');
    for (let i = stack.length - 1; i >= 0; i--) out += stack[i] === '{' ? '}' : ']';
    return out;
  }

  // Render the markdown body, then (if present) the test-case cards + xlsx button.
  function appendAssistantBody(bubble, msg) {
    const tc = extractTestCases(msg.content);
    const body = tc ? tc.cleaned : msg.content;
    if (body) {
      const mdEl = document.createElement('div');
      mdEl.className = 'markdown';
      mdEl.innerHTML = renderMarkdownSafe(body);
      bubble.appendChild(mdEl);
    }
    if (tc) bubble.appendChild(buildTestCaseView(tc.data, msg));
    return tc;
  }

  function resultBadgeClass(result) {
    const r = (result || '').toLowerCase();
    if (r.includes('fail')) return 'fail';
    if (r.includes('pass')) return 'pass';
    return 'neutral';
  }

  function groupTypeClass(type) {
    const t = (type || '').toLowerCase();
    if (t === 'negative') return 'neg';
    if (t === 'edge') return 'edge';
    return 'pos';
  }

  function buildTestCaseView(data, msg) {
    const vi = msg.language !== 'English';
    const L = vi
      ? { precondition: 'Điều kiện', expected: 'Kết quả mong đợi', steps: 'Bước thực hiện', note: 'Ghi chú', dl: 'Tải .xlsx' }
      : { precondition: 'Precondition', expected: 'Expected result', steps: 'Steps', note: 'Note', dl: 'Download .xlsx' };

    const wrap = document.createElement('div');
    wrap.className = 'testcases';

    if (data.title) {
      const h = document.createElement('div');
      h.className = 'testcases-title';
      h.textContent = data.title;
      wrap.appendChild(h);
    }

    (data.groups || []).forEach((group) => {
      const groupEl = document.createElement('div');
      groupEl.className = 'tc-group';

      const head = document.createElement('div');
      head.className = `tc-group-head ${groupTypeClass(group.type)}`;
      head.textContent = group.name || '';
      groupEl.appendChild(head);

      (group.cases || []).forEach((tc) => {
        groupEl.appendChild(buildTestCaseCard(tc, group, L));
      });
      wrap.appendChild(groupEl);
    });

    wrap.appendChild(buildTestCaseActions(data, L));
    return wrap;
  }

  function buildTestCaseCard(tc, group, L) {
    const card = document.createElement('div');
    card.className = 'tc-card';

    const header = document.createElement('div');
    header.className = 'tc-card-head';
    if (tc.id) {
      const idEl = document.createElement('span');
      idEl.className = `tc-id ${groupTypeClass(group.type)}`;
      idEl.textContent = tc.id;
      header.appendChild(idEl);
    }
    const titleEl = document.createElement('span');
    titleEl.className = 'tc-card-title';
    titleEl.textContent = tc.title || '';
    header.appendChild(titleEl);
    card.appendChild(header);

    const grid = document.createElement('div');
    grid.className = 'tc-grid';
    grid.appendChild(tcField(L.precondition, tc.precondition));

    const expectedField = document.createElement('div');
    expectedField.className = 'tc-field';
    const expLabel = document.createElement('div');
    expLabel.className = 'tc-field-label';
    expLabel.textContent = L.expected;
    const expBody = document.createElement('div');
    expBody.className = 'tc-field-value';
    if (tc.result) {
      const badge = document.createElement('span');
      badge.className = `tc-result ${resultBadgeClass(tc.result)}`;
      badge.textContent = tc.result;
      expBody.appendChild(badge);
    }
    if (tc.expected) {
      const txt = document.createElement('span');
      txt.textContent = tc.expected;
      expBody.appendChild(txt);
    }
    expectedField.appendChild(expLabel);
    expectedField.appendChild(expBody);
    grid.appendChild(expectedField);
    card.appendChild(grid);

    if (tc.steps) {
      const stepsField = tcField(L.steps, tc.steps);
      stepsField.classList.add('tc-field-full');
      card.appendChild(stepsField);
    }
    if (tc.note) {
      const noteField = document.createElement('div');
      noteField.className = 'tc-field tc-field-full tc-note';
      const nLabel = document.createElement('div');
      nLabel.className = 'tc-field-label';
      nLabel.textContent = L.note;
      const nBody = document.createElement('div');
      nBody.className = 'tc-field-value';
      nBody.textContent = '⚠ ' + tc.note;
      noteField.appendChild(nLabel);
      noteField.appendChild(nBody);
      card.appendChild(noteField);
    }
    return card;
  }

  function tcField(label, value) {
    const field = document.createElement('div');
    field.className = 'tc-field';
    const lbl = document.createElement('div');
    lbl.className = 'tc-field-label';
    lbl.textContent = label;
    const val = document.createElement('div');
    val.className = 'tc-field-value';
    val.textContent = value || '—';
    field.appendChild(lbl);
    field.appendChild(val);
    return field;
  }

  function buildTestCaseActions(data, L) {
    const actions = document.createElement('div');
    actions.className = 'report-actions tc-actions';
    const dlBtn = document.createElement('button');
    dlBtn.type = 'button';
    dlBtn.className = 'report-action-btn tc-xlsx-btn';
    dlBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>
      </svg>
      ${L.dl}`;
    dlBtn.addEventListener('click', () => downloadTestCasesXlsx(data, dlBtn));
    actions.appendChild(dlBtn);
    return actions;
  }

  function testCaseRows(data) {
    // Flatten groups → rows for xlsx / markdown export.
    const rows = [];
    (data.groups || []).forEach((group) => {
      (group.cases || []).forEach((tc) => {
        rows.push({
          Group: group.name || '',
          ID: tc.id || '',
          'Test case': tc.title || '',
          'Precondition / Điều kiện': tc.precondition || '',
          'Steps / Bước thực hiện': tc.steps || '',
          'Expected / Kết quả mong đợi': tc.expected || '',
          Result: tc.result || '',
          'Note / Ghi chú': tc.note || '',
        });
      });
    });
    return rows;
  }

  function downloadTestCasesXlsx(data, btn) {
    if (typeof window.XLSX === 'undefined') {
      if (btn) {
        const label = btn.querySelector('svg') ? btn.lastChild : btn;
        const prev = label.textContent;
        label.textContent = ' (đang tải thư viện…)';
        setTimeout(() => { label.textContent = prev; }, 2000);
      }
      return;
    }
    const rows = testCaseRows(data);
    const ws = window.XLSX.utils.json_to_sheet(rows);
    // Reasonable column widths so the sheet is readable on open.
    ws['!cols'] = [
      { wch: 22 }, { wch: 12 }, { wch: 34 }, { wch: 36 },
      { wch: 40 }, { wch: 40 }, { wch: 14 }, { wch: 30 },
    ];
    const wb = window.XLSX.utils.book_new();
    window.XLSX.utils.book_append_sheet(wb, ws, 'Test cases');
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    window.XLSX.writeFile(wb, `zp-release-guard-testcases-${stamp}.xlsx`);
  }

  function testCasesToMarkdown(data) {
    // Human-readable markdown used for Copy / .md export (replaces the JSON block).
    const out = [];
    if (data.title) out.push(`### ${data.title}`, '');
    (data.groups || []).forEach((group) => {
      if (group.name) out.push(`**${group.name}**`, '');
      out.push('| ID | Test case | Điều kiện | Bước thực hiện | Kết quả mong đợi | Result | Ghi chú |');
      out.push('|---|---|---|---|---|---|---|');
      (group.cases || []).forEach((tc) => {
        const cell = (v) => String(v || '').replace(/\n/g, '<br>').replace(/\|/g, '\\|');
        out.push(`| ${cell(tc.id)} | ${cell(tc.title)} | ${cell(tc.precondition)} | ${cell(tc.steps)} | ${cell(tc.expected)} | ${cell(tc.result)} | ${cell(tc.note)} |`);
      });
      out.push('');
    });
    return out.join('\n');
  }

  // Content used by Copy / .md export: the JSON test-case block is swapped for a
  // readable markdown table so exports never contain raw JSON.
  function exportableContent(msg) {
    const tc = extractTestCases(msg.content);
    if (!tc) return msg.content;
    const table = testCasesToMarkdown(tc.data);
    return tc.cleaned ? `${tc.cleaned}\n\n${table}` : table;
  }

  function renderTyping() {
    const wrap = document.createElement('div');
    wrap.className = 'message assistant';
    wrap.innerHTML = `
      <div class="avatar">
        <img src="/zalopay.png" alt="ZaloPay" width="32" height="32">
      </div>
      <div class="bubble">
        <div class="typing"><span></span><span></span><span></span></div>
        <span class="typing-label">Đang phân tích…</span>
      </div>`;
    messagesEl.appendChild(wrap);
    scrollToBottom();
    return wrap;
  }

  function scrollToBottom(smooth = true) {
    const wrapper = document.querySelector('.messages-wrapper');
    if (!wrapper) return;
    wrapper.scrollTo({
      top: wrapper.scrollHeight,
      behavior: smooth ? 'smooth' : 'instant',
    });
  }

  function markdownToText(md) {
    // Strip markdown formatting to plain text for "Copy" (the .md download keeps
    // the raw markdown). Preserves line breaks and list/table readability.
    let t = String(md);
    t = t.replace(/```[\s\S]*?```/g, (m) => m.replace(/```[^\n]*/g, '').trim()); // code fences
    t = t.replace(/`([^`]+)`/g, '$1');                       // inline code
    t = t.replace(/^\s{0,3}#{1,6}\s*/gm, '');                // headings
    t = t.replace(/\*\*([^*]+)\*\*/g, '$1').replace(/__([^_]+)__/g, '$1'); // bold
    t = t.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1$2');         // italic *
    t = t.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');           // links -> text
    t = t.replace(/^[ \t]*>[ \t]?/gm, '');                   // blockquote
    t = t.replace(/^[ \t]*\|?[ \t:|]*-{2,}[ \t:|-]*$/gm, ''); // table separator rows
    t = t.replace(/^[ \t]*\|(.+)\|[ \t]*$/gm, (m, row) =>    // table rows -> spaced
      row.split('|').map((s) => s.trim()).join('  '));
    t = t.replace(/\|/g, ' ');
    t = t.replace(/\n{3,}/g, '\n\n');                        // collapse blank lines
    return t.trim();
  }

  async function copyToClipboard(text) {
    // navigator.clipboard only works on HTTPS / localhost. Fall back to a hidden
    // textarea + execCommand so copy still works on http://<lan-ip> deployments.
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch { /* fall through to legacy path */ }
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }

  function downloadMarkdown(text) {
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zp-release-guard-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function renderMarkdownSafe(text) {
    if (typeof window.marked === 'undefined' || typeof window.DOMPurify === 'undefined') {
      // Libraries still loading — fall back to escaped plain text
      const div = document.createElement('div');
      div.style.whiteSpace = 'pre-wrap';
      div.textContent = text;
      return div.outerHTML;
    }
    const renderer = new window.marked.Renderer();
    renderer.listitem = (text, task) => `<li>${task ? text.replace(/^<input[^>]*>\s*/, '') : text}</li>\n`;
    window.marked.setOptions({
      gfm: true,
      breaks: true,
      headerIds: false,
      mangle: false,
      renderer,
    });
    const html = window.marked.parse(text);
    return window.DOMPurify.sanitize(html, {
      USE_PROFILES: { html: true },
      ALLOWED_ATTR: ['href', 'title', 'target', 'rel', 'colspan', 'rowspan', 'align', 'class'],
    });
  }
})();
