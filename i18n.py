"""
AegisVault Uluslararası Dil Desteği (i18n)
Desteklenen Diller: Türkçe (tr), English (en), Русский (ru)
"""

LANGUAGES = {
    "tr": "🇹🇷 Türkçe",
    "en": "🇬🇧 English",
    "ru": "🇷🇺 Русский"
}

TRANSLATIONS = {
    "tr": {
        "app_title": "AegisVault 3.5 - Askeri Düzey Güvenlik & Kripto Ekosistemi",
        "tagline": "AES-256-GCM + scrypt (BIP-38) Destekli Güvenlik Kasası",
        "status_active": "● AES-256-GCM | AKTİF",
        "status_decoy": "● DURESS / SAHTE MOD",
        "nav_vault": "🔑 Güvenli Kasa",
        "nav_portfolio": "📊 Kripto Bakiye & Fiyat",
        "nav_p2p_chat": "💬 Canlı P2P Güvenli Sohbet",
        "nav_shamir": "🧩 Shamir (SSS) Yedekleme",
        "nav_bip39": "🔍 BIP-39 Seed Analiz",
        "nav_audit": "📜 Askeri Olay Günlüğü (Audit)",
        "nav_lock": "🔒 Kasayı Kilitle",
        "btn_check_update": "⚡ Güncellemeleri Denetle",
        "inactivity_notice": "⏱️ 2 dk hareketsizlikte otomatik kilitlenir.",
        
        # Dashboard
        "search_placeholder": "🔍 Başlık veya kategoriye göre filtrele...",
        "total_items": "Kayıtlı Öğe",
        "btn_add_secret": "➕ Yeni Veri Ekle",
        "empty_vault_msg": "Henüz kayıtlı bir veri bulunamadı.\n'Yeni Veri Ekle' butonuna basarak ilk Bitcoin tohumunuzu veya şifrenizi ekleyin.",
        "btn_show": "👁️ Göster",
        "btn_hide": "👁️ Gizle",
        "btn_copy": "📋",
        "copied_alert": "Panoya kopyalandı!",
        "delete_confirm": "'{title}' kaydını kalıcı olarak silmek istiyor musunuz?",
        
        # Profil & Kilit
        "profile_label": "Kullanıcı Profili:",
        "btn_new_profile": "➕ Yeni Profil Oluştur",
        "profile_name_placeholder": "Kullanıcı Adı (Örn: Ahmet, Finans, Kisisel)...",
        "bind_hw_label": "🔒 Bu profili sadece bu bilgisayara kilitle (Donanım İmzası)",
        "setup_title": "🛡️ Yeni Kullanıcı Kasası Kurulumu",
        "setup_desc": "Tüm Bitcoin tohumları ve verileriniz AES-256-GCM + scrypt ile diskinizde şifrelenir.\nİsteğe bağlı olarak baskı altındayken girilecek bir 'Tehdit Parolası' belirleyebilirsiniz.",
        "master_pass_placeholder": "Ana Parola...",
        "confirm_pass_placeholder": "Ana Parolayı Doğrulayın...",
        "duress_pass_placeholder": "Tehdit Parolası (Opsiyonel - Sahte Kasa)...",
        "btn_suggest_pass": "🎲 Güçlü Askeri Parola Öner",
        "btn_create_vault": "KASAYI OLUŞTUR VE BAŞLAT",
        "unlock_title": "🔒 Aegis Vault Kilitli",
        "unlock_desc": "AES-256-GCM ile şifrelenmiş kullanıcı kasası seçildi.\nErişmek için belirlediğiniz parolayı girin.",
        "unlock_btn": "KASANIN KİLİDİNİ AÇ",
        
        # Modal
        "modal_add_title": "➕ Kasaya Yeni Veri Ekle",
        "field_title": "Kayıt Başlığı (Örn: Ledger Bitcoin Tohumu)",
        "field_secret": "Gizli Değer / Parola / Seed Phrase:",
        "btn_generate_pass": "🎲 32 Karakter Askeri Şifre Üret (CSPRNG)",
        "field_notes": "Ek Notlar (İsteğe bağlı)",
        "btn_save_vault": "KASAYA GÜVENLİ KAYDET",
        
        # Shamir
        "shamir_title": "🧩 Shamir's Secret Sharing (Eşikli Parçalama)",
        "shamir_desc": "💡 Bu Ne İşe Yarar?\nKritik Bitcoin tohumunuzu N parçaya böler. Örneğin 3-of-5 sisteminde 5 parça üretilir; herhangi 3 parça birleşmeden şifre ASLA çözülemez. 2 parça çalınsa veya yansa bile paranız güvendedir.",
        "tab_split": "Parçalara Böl (Split)",
        "tab_combine": "Birleştir & Kurtar (Combine)",
        "label_n": "Toplam Parça (N):",
        "label_k": "Gereken Eşik (K):",
        "btn_do_split": "PARÇALARI OLUŞTUR (SSS SPLIT)",
        "btn_do_combine": "PARÇALARI BİRLEŞTİR & KURTAR",
        
        # Portföy
        "portfolio_title": "📊 Soğuk Cüzdan Bakiye & Piyasa Takibi",
        "portfolio_desc": "💡 Güvenlik & Doğrulama Notu:\nBuraya ASLA özel anahtar (private key) girmeyiniz. Sadece genel adresinizi (Public Address - bc1q..., 0x...) giriniz. Sistem adresin sağlama toplamını (checksum) denetler ve Blockchain.info üzerinden gerçek canlı bakiyeyi çeker.",
        "btn_add_address": "➕ Adres Ekle",
        "total_portfolio_val": "Toplam Portföy Değeri",
        "crypto_price_live": "Canlı Kripto Fiyatları",
        "btn_refresh_prices": "🔄 Fiyatları & Bakiyeleri Güncelle",
        
        # Canlı P2P Chat
        "p2p_chat_title": "💬 Küresel Uçtan Uca Şifreli Sohbet Ağı (Türkiye ↔ Dünya)",
        "p2p_chat_desc": "💡 Bu Ne İşe Yarar?\nDünyanın neresinde olursanız olun (Türkiye ↔ İngiltere vb.), port açmaya veya IP yapılandırmasına gerek olmadan anında canlı ve uçtan uca AES-256-GCM şifreli iletişim kurar. Ortak 'Oda Adı' ve 'Oda Şifresi' belirlemeniz yeterlidir. İletilen tüm veri askeri kripto ile zırhlandığı için aracı sunucu yalnızca anlamsız şifreli metin (AEGIS-MSG-v1:...) görür.",
        "p2p_tab_host": "Oda Kur (Host)",
        "p2p_tab_join": "Odaya Katıl (Join)",
        "p2p_room_key": "Oda Güvenlik Parolası:",
        "btn_host_start": "Odayı Başlat (Dinle)",
        "btn_join_start": "Odaya Bağlan",
        "btn_chat_connect": "🟢 Odaya Bağlan (Dünya Çapı)",
        "btn_chat_disconnect": "🔴 Odadan Ayrıl",
        "chat_nick": "Rumuz:",
        "chat_room_name": "Oda Adı (Kanal):",
        "chat_room_key": "Oda Şifresi (AES-256):",
        "btn_send": "GÖNDER",
        "security_info_title": "🛡️ Askeri Kriptografi Kılavuzu"
    },
    
    "en": {
        "app_title": "AegisVault 3.5 - Military Security & Crypto Suite",
        "tagline": "AES-256-GCM + scrypt (BIP-38) Encrypted Vault",
        "status_active": "● AES-256-GCM | ACTIVE",
        "status_decoy": "● DURESS / DECOY MODE",
        "nav_vault": "🔑 Secure Vault",
        "nav_portfolio": "📊 Crypto Balances & Prices",
        "nav_p2p_chat": "💬 Live P2P Encrypted Chat",
        "nav_shamir": "🧩 Shamir (SSS) Backup",
        "nav_bip39": "🔍 BIP-39 Seed Analyzer",
        "nav_audit": "📜 Military Audit Trail (Hash-Chain)",
        "nav_lock": "🔒 Lock Vault",
        "btn_check_update": "⚡ Check for Updates",
        "inactivity_notice": "⏱️ Auto-locks after 2 min of inactivity.",
        
        # Dashboard
        "search_placeholder": "🔍 Filter by title or category...",
        "total_items": "Saved Items",
        "btn_add_secret": "➕ Add New Secret",
        "empty_vault_msg": "No saved records found yet.\nClick 'Add New Secret' to store your first Bitcoin seed or password.",
        "btn_show": "👁️ Show",
        "btn_hide": "👁️ Hide",
        "btn_copy": "📋",
        "copied_alert": "Copied to clipboard!",
        "delete_confirm": "Are you sure you want to permanently delete '{title}'?",
        
        # Profiles
        "profile_label": "User Profile:",
        "btn_new_profile": "➕ Create New Profile",
        "profile_name_placeholder": "Username (e.g. Alice, Personal, Finance)...",
        "bind_hw_label": "🔒 Bind this profile exclusively to this PC (Hardware Fingerprint)",
        "setup_title": "🛡️ New User Vault Setup",
        "setup_desc": "All Bitcoin seeds and data are encrypted locally on disk using AES-256-GCM + scrypt.\nYou can also optionally set a 'Duress Password' for plausible deniability.",
        "master_pass_placeholder": "Master Password...",
        "confirm_pass_placeholder": "Confirm Master Password...",
        "duress_pass_placeholder": "Duress Password (Optional - Decoy Vault)...",
        "btn_suggest_pass": "🎲 Suggest Military Password",
        "btn_create_vault": "CREATE AND INITIALIZE VAULT",
        "unlock_title": "🔒 Aegis Vault Locked",
        "unlock_desc": "AES-256-GCM encrypted user vault selected.\nEnter your master password to unlock.",
        "unlock_btn": "UNLOCK VAULT",
        
        # Modal
        "modal_add_title": "➕ Add New Secure Secret",
        "field_title": "Title (e.g. Ledger Bitcoin Seed)",
        "field_secret": "Secret / Seed / Private Key:",
        "btn_generate_pass": "🎲 Generate 32-Char Military Password (CSPRNG)",
        "field_notes": "Additional Notes (Optional)",
        "btn_save_vault": "SECURELY SAVE TO VAULT",
        
        # Shamir
        "shamir_title": "🧩 Shamir's Secret Sharing (Threshold Cryptography)",
        "shamir_desc": "💡 How Does This Work?\nSplits your Bitcoin seed into N shares. For example, in a 3-of-5 setup, 5 shares are generated; any 3 shares must be combined to recover the secret. Even if 2 shares are stolen or lost, your funds remain 100% secure.",
        "tab_split": "Split Secret",
        "tab_combine": "Combine & Recover",
        "label_n": "Total Shares (N):",
        "label_k": "Required Threshold (K):",
        "btn_do_split": "GENERATE SHARES (SSS SPLIT)",
        "btn_do_combine": "COMBINE SHARES & RECOVER",
        
        # Portfolio
        "portfolio_title": "📊 Cold Storage Portfolio & Live Prices",
        "portfolio_desc": "💡 Security & Verification Note:\nNEVER enter private keys here. Only enter public addresses (e.g., bc1q..., 0x...). The system verifies checksums and fetches live balances directly from Blockchain.info nodes.",
        "btn_add_address": "➕ Add Address",
        "total_portfolio_val": "Total Portfolio Value",
        "crypto_price_live": "Live Cryptocurrency Prices",
        "btn_refresh_prices": "🔄 Refresh Prices & Balances",
        
        # Live P2P Chat
        "p2p_chat_title": "💬 Global End-to-End Encrypted Chat (Turkey ↔ Worldwide)",
        "p2p_chat_desc": "💡 How Does This Work?\nConnects computers anywhere across the globe (e.g. Turkey ↔ UK) instantly without port forwarding or IP exposure. Simply agree on a 'Room Name' and 'Room Key'. All messages are armored with AES-256-GCM before transmission; the relay broker only sees ciphertext (AEGIS-MSG-v1:...).",
        "p2p_tab_host": "Host Room",
        "p2p_tab_join": "Join Room",
        "p2p_room_key": "Room Security Passkey:",
        "btn_host_start": "Start Room (Listen)",
        "btn_join_start": "Connect to Room",
        "btn_chat_connect": "🟢 Connect to Room (Global)",
        "btn_chat_disconnect": "🔴 Leave Room",
        "chat_nick": "Nickname:",
        "chat_room_name": "Room Name (Channel):",
        "chat_room_key": "Room Key (AES-256):",
        "btn_send": "SEND",
        "security_info_title": "🛡️ Military Cryptography Guide"
    },
    
    "ru": {
        "app_title": "AegisVault 3.5 - Военная Безопасность и Криптосистема",
        "tagline": "Шифрованное хранилище AES-256-GCM + scrypt (BIP-38)",
        "status_active": "● AES-256-GCM | АКТИВНО",
        "status_decoy": "● РЕЖИМ ПРИНУЖДЕНИЯ (ЛОЖНЫЙ)",
        "nav_vault": "🔑 Безопасное хранилище",
        "nav_portfolio": "📊 Баланс и Цены Криптовалют",
        "nav_p2p_chat": "💬 Живой P2P Зашифрованный Чат",
        "nav_shamir": "🧩 Разделение Шамира (SSS)",
        "nav_bip39": "🔍 Анализ BIP-39 Seed",
        "nav_audit": "📜 Военный Журнал Аудита (Audit)",
        "nav_lock": "🔒 Заблокировать",
        "btn_check_update": "⚡ Проверить обновления",
        "inactivity_notice": "⏱️ Автоблокировка через 2 мин бездействия.",
        
        # Dashboard
        "search_placeholder": "🔍 Поиск по названию или категории...",
        "total_items": "Сохраненные записи",
        "btn_add_secret": "➕ Добавить запись",
        "empty_vault_msg": "Записей пока нет.\nНажмите 'Добавить запись', чтобы сохранить первый Bitcoin seed или пароль.",
        "btn_show": "👁️ Показать",
        "btn_hide": "👁️ Скрыть",
        "btn_copy": "📋",
        "copied_alert": "Скопировано в буфер обмена!",
        "delete_confirm": "Вы уверены, что хотите удалить '{title}'?",
        
        # Profiles
        "profile_label": "Профиль пользователя:",
        "btn_new_profile": "➕ Создать новый профиль",
        "profile_name_placeholder": "Имя пользователя (напр. Иван, Личный)...",
        "bind_hw_label": "🔒 Привязать профиль только к этому ПК (Отпечаток железа)",
        "setup_title": "🛡️ Настройка нового профиля",
        "setup_desc": "Все сид-фразы и данные шифруются локально на диске с помощью AES-256-GCM + scrypt.\nВы также можете задать 'Пароль под принуждением'.",
        "master_pass_placeholder": "Мастер-пароль...",
        "confirm_pass_placeholder": "Подтвердите пароль...",
        "duress_pass_placeholder": "Пароль принуждения (Ложное хранилище)...",
        "btn_suggest_pass": "🎲 Сгенерировать военный пароль",
        "btn_create_vault": "СОЗДАТЬ ХРАНИЛИЩЕ",
        "unlock_title": "🔒 Aegis Vault Заблокирован",
        "unlock_desc": "Выбран зашифрованный профиль.\nВведите пароль для разблокировки.",
        "unlock_btn": "РАЗБЛОКИРОВАТЬ",
        
        # Modal
        "modal_add_title": "➕ Добавить новую запись",
        "field_title": "Название (напр. Ledger Bitcoin Seed)",
        "field_secret": "Секрет / Сид-фраза / Пароль:",
        "btn_generate_pass": "🎲 Сгенерировать 32-значный пароль (CSPRNG)",
        "field_notes": "Заметки (необязательно)",
        "btn_save_vault": "НАДЕЖНО СОХРАНИТЬ",
        
        # Shamir
        "shamir_title": "🧩 Разделение секрета Шамира (SSS)",
        "shamir_desc": "💡 Как это работает?\nМатематически разделяет сид-фразу на N частей. Например, при схеме 3 из 5 для восстановления нужны любые 3 части. Даже при потере 2 частей данные в полной безопасности.",
        "tab_split": "Разделить (Split)",
        "tab_combine": "Собрать и восстановить",
        "label_n": "Всего частей (N):",
        "label_k": "Порог восстановления (K):",
        "btn_do_split": "СОЗДАТЬ ЧАСТИ (SSS SPLIT)",
        "btn_do_combine": "СОБРАТЬ И ВОССТАНОВИТЬ",
        
        # Portfolio
        "portfolio_title": "📊 Холодный Кошелек и Цены",
        "portfolio_desc": "💡 Безопасность и проверка:\nНИКОГДА не вводите сюда приватные ключи! Указывайте только публичные адреса (напр. bc1q..., 0x...). Система проверяет контрольную сумму и запрашивает актуальный баланс в сети Bitcoin.",
        "btn_add_address": "➕ Добавить адрес",
        "total_portfolio_val": "Общая стоимость портфеля",
        "crypto_price_live": "Актуальные курсы криптовалют",
        "btn_refresh_prices": "🔄 Обновить цены и балансы",
        
        # P2P Chat
        "p2p_chat_title": "💬 Глобальный зашифрованный чат (Турция ↔ Весь мир)",
        "p2p_chat_desc": "💡 Как это работает?\nМгновенно связывает участников по всему миру (напр. Турция ↔ Великобритания) без проброса портов и IP. Достаточно указать общее 'Имя комнаты' и 'Пароль комнаты'. Все сообщения шифруются AES-256-GCM; релей видит только шифротекст (AEGIS-MSG-v1:...).",
        "p2p_tab_host": "Создать комнату (Host)",
        "p2p_tab_join": "Присоединиться (Join)",
        "p2p_room_key": "Пароль комнаты:",
        "btn_host_start": "Запустить комнату (Слушать)",
        "btn_join_start": "Подключиться к комнате",
        "btn_chat_connect": "🟢 Войти в комнату (Глобально)",
        "btn_chat_disconnect": "🔴 Выйти из комнаты",
        "chat_nick": "Ваш ник:",
        "chat_room_name": "Имя комнаты (Канал):",
        "chat_room_key": "Пароль (AES-256):",
        "btn_send": "ОТПРАВИТЬ",
        "security_info_title": "🛡️ Справочник по криптографии"
    }
}

CURRENT_LANG = "tr"


def get_text(key: str, **kwargs) -> str:
    lang_dict = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["tr"])
    template = lang_dict.get(key, TRANSLATIONS["en"].get(key, key))
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template


def set_language(lang_code: str):
    global CURRENT_LANG
    if lang_code in TRANSLATIONS:
        CURRENT_LANG = lang_code
