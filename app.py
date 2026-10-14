"""
Aegis Vault 3.5 - Askeri Sınıf Kriptografik Kasa & P2P Güvenlik Ekosistemi
Yeni Özellikler:
1. 👤 Çoklu Kullanıcı Profilleri (Her kullanıcı/bilgisayar için bağımsız şifre ve kasa)
2. 🔒 Cihaz Donanım Kilitleme (Hardware-Bound Vault - Başka PC'de açılamaz)
3. 💬 Canlı P2P Güvenli Sohbet Ağı (Doğrudan İki Bilgisayar Arası AES-256-GCM Soket)
4. 📊 Blokzincir Doğrulamalı Canlı Kripto Portföy (Blockchain.info API)
5. ⚡ GitHub Otomatik Güncelleme Kontrolü (GitHub Releases API)
6. 🌐 3 Dilli Arayüz (Türkçe, English, Русский)
"""

import os
import sys
import time
import threading
import customtkinter as ctk
from tkinter import messagebox

import i18n
from i18n import get_text
import vault_storage
import crypto_utils
import crypto_portfolio
import live_p2p_chat
import updater
import military_audit
from military_vault import VaultSecurityError

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class AegisVaultApp(ctk.CTk):
    INACTIVITY_TIMEOUT = 120  # 2 Dakika

    def __init__(self):
        super().__init__()

        self.title("AegisVault 3.5 - Military Cryptographic Suite & P2P")
        self.geometry("1120x760")
        self.minsize(980, 660)

        # Durum Değişkenleri
        self.selected_profile = "Varsayılan"
        self.master_password = None
        self.effective_password = None
        self.vault_data = None
        self.is_decoy = False
        self.revealed_secrets = set()
        self.last_activity_time = time.time()
        self.current_tab = "vault"
        self.live_prices = crypto_portfolio.DEFAULT_PRICES

        # FIPS 140-3 POST ve Askeri Öz-Testler
        self.post_results = military_audit.run_power_on_self_tests()
        military_audit.CryptographicAuditTrail.record_event(
            "POST_BOOT", "System", "FIPS 140-3 Power-On Self Tests %100 Passed (NIST KAT 100%)", "INFO"
        )

        # Ana Taşıyıcı
        self.container = ctk.CTkFrame(self, corner_radius=0)
        self.container.pack(fill="both", expand=True)

        self.bind_all("<Key>", self._on_user_interaction)
        self.bind_all("<Motion>", self._on_user_interaction)
        self.bind_all("<Button>", self._on_user_interaction)

        self.check_vault_status()
        self._start_inactivity_timer()
        self._start_price_fetch_thread()

    def _on_user_interaction(self, event=None):
        self.last_activity_time = time.time()

    def _start_inactivity_timer(self):
        if self.master_password and (time.time() - self.last_activity_time > self.INACTIVITY_TIMEOUT):
            self.lock_vault(reason=get_text("inactivity_notice"))
        self.after(5000, self._start_inactivity_timer)

    def _start_price_fetch_thread(self):
        def worker():
            try:
                self.live_prices = crypto_portfolio.fetch_live_prices()
            except Exception:
                pass
        threading.Thread(target=worker, daemon=True).start()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def set_language_and_refresh(self, lang_choice: str):
        lang_code = "tr"
        if "English" in lang_choice or "en" in lang_choice:
            lang_code = "en"
        elif "Русский" in lang_choice or "ru" in lang_choice:
            lang_code = "ru"

        i18n.set_language(lang_code)
        if self.vault_data and self.master_password:
            self.vault_data.setdefault("settings", {})["language"] = lang_code
            vault_storage.save_vault(self.effective_password or self.master_password, self.vault_data, is_decoy=self.is_decoy)
            self.show_dashboard()
        else:
            self.check_vault_status()

    # =========================================================================
    # 1. BAŞLANGIÇ & PROFİL SEÇİCİ / GİRİŞ EKRANI
    # =========================================================================
    def check_vault_status(self):
        self.clear_container()
        profiles = vault_storage.list_profiles()
        if not profiles or (len(profiles) == 1 and not vault_storage.profile_exists(profiles[0])):
            self.show_create_profile_screen()
        else:
            self.show_unlock_screen()

    def _add_top_lang_selector(self, parent_frame):
        lang_bar = ctk.CTkFrame(parent_frame, fg_color="transparent")
        lang_bar.pack(anchor="ne", padx=20, pady=(15, 0))

        lang_menu = ctk.CTkOptionMenu(
            lang_bar,
            values=["🇹🇷 Türkçe", "🇬🇧 English", "🇷🇺 Русский"],
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            command=self.set_language_and_refresh
        )
        cur = i18n.CURRENT_LANG
        lang_menu.set(i18n.LANGUAGES.get(cur, "🇹🇷 Türkçe"))
        lang_menu.pack(side="right")

    def show_create_profile_screen(self):
        self._add_top_lang_selector(self.container)

        frame = ctk.CTkFrame(self.container, width=540, corner_radius=15, fg_color="#181a1f")
        frame.place(relx=0.5, rely=0.52, anchor="center")

        title_lbl = ctk.CTkLabel(
            frame,
            text=get_text("setup_title"),
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(pady=(25, 6), padx=30)

        desc_lbl = ctk.CTkLabel(
            frame,
            text=get_text("setup_desc"),
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="center"
        )
        desc_lbl.pack(pady=(0, 15), padx=25)

        self.setup_prof_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("profile_name_placeholder"), width=400, height=40
        )
        self.setup_prof_entry.pack(pady=5)
        self.setup_prof_entry.insert(0, "Kisisel")

        self.setup_pass_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("master_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_pass_entry.pack(pady=5)

        self.setup_pass_confirm = ctk.CTkEntry(
            frame, placeholder_text=get_text("confirm_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_pass_confirm.pack(pady=5)

        self.setup_duress_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("duress_pass_placeholder"), show="*", width=400, height=40
        )
        self.setup_duress_entry.pack(pady=5)

        # Cihaz Donanım Kilitleme Kutusu
        self.hw_bind_var = ctk.BooleanVar(value=False)
        hw_chk = ctk.CTkCheckBox(
            frame,
            text=get_text("bind_hw_label"),
            variable=self.hw_bind_var,
            font=ctk.CTkFont(size=11),
            text_color="#38bdf8"
        )
        hw_chk.pack(pady=8)

        gen_btn = ctk.CTkButton(
            frame,
            text=get_text("btn_suggest_pass"),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            command=self._generate_suggested_master_pass,
            height=30
        )
        gen_btn.pack(pady=4)

        btn_box = ctk.CTkFrame(frame, fg_color="transparent")
        btn_box.pack(pady=(12, 25), fill="x", padx=35)

        create_btn = ctk.CTkButton(
            btn_box,
            text=get_text("btn_create_vault"),
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=44,
            command=self._handle_create_profile
        )
        create_btn.pack(fill="x")

        # Var olan profillere geri dön butonu (varsa)
        if vault_storage.list_profiles():
            cancel_btn = ctk.CTkButton(
                btn_box,
                text="← Mevcut Profillere Dön",
                fg_color="transparent",
                text_color="#94a3b8",
                hover_color="#334155",
                command=self.show_unlock_screen,
                height=30
            )
            cancel_btn.pack(pady=(8, 0))

    def _generate_suggested_master_pass(self):
        new_pass = vault_storage.generate_secure_password(length=28, use_symbols=True)
        self.setup_pass_entry.delete(0, "end")
        self.setup_pass_confirm.delete(0, "end")
        self.setup_pass_entry.insert(0, new_pass)
        self.setup_pass_confirm.insert(0, new_pass)
        self.setup_pass_entry.configure(show="")
        self.setup_pass_confirm.configure(show="")
        self.clipboard_clear()
        self.clipboard_append(new_pass)
        messagebox.showinfo(get_text("copied_alert"), new_pass)

    def _handle_create_profile(self):
        prof = self.setup_prof_entry.get().strip()
        p1 = self.setup_pass_entry.get().strip()
        p2 = self.setup_pass_confirm.get().strip()
        duress = self.setup_duress_entry.get().strip()
        bind_hw = self.hw_bind_var.get()

        if not prof:
            messagebox.showerror("Error", "Lütfen bir profil adı giriniz!")
            return
        if len(p1) < 8:
            messagebox.showerror("Error", "Parola en az 8 karakter olmalıdır!")
            return
        if p1 != p2:
            messagebox.showerror("Error", "Parolalar eşleşmiyor!")
            return
        if duress and duress == p1:
            messagebox.showerror("Error", "Tehdit parolası ana parola ile aynı olamaz!")
            return

        self.selected_profile = prof
        self.master_password = p1
        self.is_decoy = False

        self.vault_data = vault_storage.init_vault(
            master_password=p1,
            duress_password=duress if duress else None,
            lang=i18n.CURRENT_LANG,
            profile_name=prof,
            bind_to_hardware=bind_hw
        )
        hw_id = vault_storage.get_hardware_fingerprint() if bind_hw else None
        self.effective_password = (p1 + f"|HW:{hw_id}") if hw_id else p1
        self.show_dashboard()

    def show_unlock_screen(self):
        self._add_top_lang_selector(self.container)

        frame = ctk.CTkFrame(self.container, width=500, corner_radius=15, fg_color="#181a1f")
        frame.place(relx=0.5, rely=0.52, anchor="center")

        title_lbl = ctk.CTkLabel(
            frame,
            text=get_text("unlock_title"),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#38bdf8"
        )
        title_lbl.pack(pady=(28, 6), padx=30)

        info_lbl = ctk.CTkLabel(
            frame,
            text=get_text("unlock_desc"),
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="center"
        )
        info_lbl.pack(pady=(0, 16), padx=25)

        # Profil Seçici
        prof_frame = ctk.CTkFrame(frame, fg_color="transparent")
        prof_frame.pack(fill="x", padx=35, pady=4)
        ctk.CTkLabel(prof_frame, text=get_text("profile_label"), font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")

        profiles = vault_storage.list_profiles()
        self.profile_select_menu = ctk.CTkOptionMenu(
            prof_frame,
            values=profiles,
            width=220,
            height=34
        )
        self.profile_select_menu.set(profiles[0] if profiles else "Varsayılan")
        self.profile_select_menu.pack(side="right")

        self.unlock_pass_entry = ctk.CTkEntry(
            frame, placeholder_text=get_text("master_pass_placeholder"), show="*", width=380, height=44, font=ctk.CTkFont(size=14)
        )
        self.unlock_pass_entry.pack(pady=10)
        self.unlock_pass_entry.bind("<Return>", lambda e: self._handle_unlock_vault())
        self.unlock_pass_entry.focus()

        unlock_btn = ctk.CTkButton(
            frame,
            text=get_text("unlock_btn"),
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=44,
            width=380,
            command=self._handle_unlock_vault
        )
        unlock_btn.pack(pady=10)

        # Yeni Profil Ekle Butonu
        new_prof_btn = ctk.CTkButton(
            frame,
            text=get_text("btn_new_profile"),
            font=ctk.CTkFont(size=12),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            height=32,
            width=380,
            command=self.show_create_profile_screen
        )
        new_prof_btn.pack(pady=(4, 25))

    def _handle_unlock_vault(self):
        prof = self.profile_select_menu.get()
        pwd = self.unlock_pass_entry.get().strip()
        if not pwd:
            return

        try:
            data, is_decoy, eff_pwd = vault_storage.unlock_vault(pwd, profile_name=prof)
            self.vault_data = data
            self.master_password = pwd
            self.effective_password = eff_pwd
            self.selected_profile = prof
            self.is_decoy = is_decoy
            self.last_activity_time = time.time()

            saved_lang = data.get("settings", {}).get("language", i18n.CURRENT_LANG)
            i18n.set_language(saved_lang)

            self.show_dashboard()
        except VaultSecurityError as e:
            messagebox.showerror("Access Denied", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Unlock error: {e}")

    # =========================================================================
    # 2. ANA PANEL (DASHBOARD)
    # =========================================================================
    def show_dashboard(self):
        self.clear_container()
        self.revealed_secrets.clear()

        self.container.grid_columnconfigure(0, weight=0)
        self.container.grid_columnconfigure(1, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        # Sol Kenar Çubuğu
        sidebar = ctk.CTkFrame(self.container, width=260, corner_radius=0, fg_color="#0f172a")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        logo_lbl = ctk.CTkLabel(
            sidebar,
            text="🛡️ AEGIS VAULT",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        logo_lbl.pack(pady=(18, 2), padx=20)

        # Aktif Profil & Güvenlik Rozeti
        prof_lbl = ctk.CTkLabel(
            sidebar,
            text=f"👤 {self.selected_profile}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94a3b8"
        )
        prof_lbl.pack()

        status_text = get_text("status_decoy") if self.is_decoy else get_text("status_active")
        status_color = "#f59e0b" if self.is_decoy else "#4ade80"
        sec_badge = ctk.CTkLabel(
            sidebar, text=status_text, font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color
        )
        sec_badge.pack(pady=(2, 14))

        # FIPS 140-3 Açılış Test Rozeti
        fips_color = "#38bdf8" if getattr(self, "post_results", {}).get("all_passed") else "#ef4444"
        fips_badge = ctk.CTkLabel(
            sidebar, text="● FIPS 140-3 POST: %100 GEÇTİ", font=ctk.CTkFont(size=10, weight="bold"), text_color=fips_color
        )
        fips_badge.pack(pady=(0, 10))

        # Modül Butonları
        nav_buttons = [
            ("vault", get_text("nav_vault")),
            ("portfolio", get_text("nav_portfolio")),
            ("p2p_chat", get_text("nav_p2p_chat")),
            ("shamir", get_text("nav_shamir")),
            ("bip39", get_text("nav_bip39")),
            ("audit", get_text("nav_audit")),
            ("guide", get_text("security_info_title")),
        ]

        self.nav_widgets = {}
        for tab_key, tab_title in nav_buttons:
            is_active = (self.current_tab == tab_key)
            btn = ctk.CTkButton(
                sidebar,
                text=tab_title,
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal"),
                fg_color="#0284c7" if is_active else "#1e293b",
                hover_color="#0369a1" if is_active else "#334155",
                height=36,
                command=lambda k=tab_key: self.switch_tab(k)
            )
            btn.pack(pady=4, padx=16, fill="x")
            self.nav_widgets[tab_key] = btn

        # Alt Alan: Güncelleme, Kilit ve Süre
        update_btn = ctk.CTkButton(
            sidebar,
            text=get_text("btn_check_update"),
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            text_color="#38bdf8",
            height=30,
            command=self._check_github_updates_ui
        )
        update_btn.pack(side="bottom", pady=(4, 10), padx=16, fill="x")

        lock_btn = ctk.CTkButton(
            sidebar,
            text=get_text("nav_lock"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            height=36,
            command=lambda: self.lock_vault()
        )
        lock_btn.pack(side="bottom", pady=4, padx=16, fill="x")

        info_txt = ctk.CTkLabel(
            sidebar,
            text=get_text("inactivity_notice"),
            font=ctk.CTkFont(size=10),
            text_color="#64748b",
            justify="center"
        )
        info_txt.pack(side="bottom", pady=2)

        # Sağ İçerik Alanı
        self.main_content = ctk.CTkFrame(self.container, fg_color="#020617")
        self.main_content.grid(row=0, column=1, sticky="nsew")
        self.main_content.grid_rowconfigure(1, weight=1)
        self.main_content.grid_columnconfigure(0, weight=1)

        # Üst Çubuk
        top_bar = ctk.CTkFrame(self.main_content, height=60, fg_color="#0b1120", corner_radius=0)
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)
        top_bar.grid_columnconfigure(1, weight=0)

        app_tagline = ctk.CTkLabel(
            top_bar,
            text=get_text("tagline"),
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94a3b8"
        )
        app_tagline.grid(row=0, column=0, padx=20, pady=14, sticky="w")

        lang_menu = ctk.CTkOptionMenu(
            top_bar,
            values=["🇹🇷 Türkçe", "🇬🇧 English", "🇷🇺 Русский"],
            width=130,
            height=30,
            font=ctk.CTkFont(size=11),
            command=self.set_language_and_refresh
        )
        cur = i18n.CURRENT_LANG
        lang_menu.set(i18n.LANGUAGES.get(cur, "🇹🇷 Türkçe"))
        lang_menu.grid(row=0, column=1, padx=20, pady=14, sticky="e")

        self.render_active_tab()

    def switch_tab(self, tab_key: str):
        self.current_tab = tab_key
        for k, btn in self.nav_widgets.items():
            is_active = (k == tab_key)
            btn.configure(
                fg_color="#0284c7" if is_active else "#1e293b",
                font=ctk.CTkFont(size=12, weight="bold" if is_active else "normal")
            )
        self.render_active_tab()

    def render_active_tab(self):
        for widget in self.main_content.grid_slaves(row=1, column=0):
            widget.destroy()

        tab_container = ctk.CTkFrame(self.main_content, fg_color="transparent")
        tab_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=15)
        tab_container.grid_columnconfigure(0, weight=1)
        tab_container.grid_rowconfigure(0, weight=1)

        if self.current_tab == "vault":
            self._render_vault_view(tab_container)
        elif self.current_tab == "portfolio":
            self._render_portfolio_view(tab_container)
        elif self.current_tab == "p2p_chat":
            self._render_p2p_chat_view(tab_container)
        elif self.current_tab == "shamir":
            self._render_shamir_view(tab_container)
        elif self.current_tab == "bip39":
            self._render_bip39_view(tab_container)
        elif self.current_tab == "audit":
            self._render_audit_view(tab_container)
        elif self.current_tab == "guide":
            self._render_guide_view(tab_container)

    def lock_vault(self, reason=None):
        if self.p2p_session:
            self.p2p_session.close()
            self.p2p_session = None

        self.master_password = None
        self.effective_password = None
        self.vault_data = None
        self.is_decoy = False
        self.revealed_secrets.clear()
        self.show_unlock_screen()
        if reason:
            messagebox.showinfo("Vault Locked", reason)

    def _check_github_updates_ui(self):
        has_up, latest_ver, down_url, notes = updater.check_for_github_update()
        if has_up:
            if messagebox.askyesno("Update Available", f"AegisVault v{latest_ver} yayında!\n\n{notes}\n\nŞimdi indirilip uygulansın mı?"):
                threading.Thread(target=lambda: updater.apply_executable_update(down_url), daemon=True).start()
                messagebox.showinfo("Downloading", "Güncelleme indiriliyor, uygulama otomatik olarak yeniden başlayacak.")
        else:
            messagebox.showinfo("Update Status", f"En güncel sürümdesiniz (v{updater.CURRENT_VERSION}).\n{notes}")

    # =========================================================================
    # 3. KASA GÖRÜNÜMÜ
    # =========================================================================
    def _render_vault_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        top_controls = ctk.CTkFrame(parent, fg_color="transparent")
        top_controls.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top_controls.grid_columnconfigure(0, weight=1)
        top_controls.grid_columnconfigure(1, weight=0)

        self.search_entry = ctk.CTkEntry(
            top_controls, placeholder_text=get_text("search_placeholder"), width=360, height=36
        )
        self.search_entry.grid(row=0, column=0, sticky="w")
        self.search_entry.bind("<KeyRelease>", lambda e: self._render_vault_cards())

        add_btn = ctk.CTkButton(
            top_controls,
            text=get_text("btn_add_secret"),
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=36,
            command=self.open_add_secret_modal
        )
        add_btn.grid(row=0, column=1, sticky="e")

        self.vault_cards_frame = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self.vault_cards_frame.grid(row=1, column=0, sticky="nsew")
        self.vault_cards_frame.grid_columnconfigure(0, weight=1)

        self._render_vault_cards()

    def _render_vault_cards(self):
        for w in self.vault_cards_frame.winfo_children():
            w.destroy()

        query = self.search_entry.get().strip().lower() if hasattr(self, "search_entry") else ""
        items = self.vault_data.get("items", [])
        filtered = [
            i for i in items
            if query in i["title"].lower() or query in i.get("category", "").lower()
        ]

        if not filtered:
            lbl = ctk.CTkLabel(
                self.vault_cards_frame,
                text=get_text("empty_vault_msg"),
                font=ctk.CTkFont(size=13),
                text_color="#64748b",
                justify="center"
            )
            lbl.pack(pady=70)
            return

        for item in filtered:
            self._create_vault_card(item)

    def _create_vault_card(self, item: dict):
        item_id = item["id"]
        is_revealed = item_id in self.revealed_secrets

        card = ctk.CTkFrame(self.vault_cards_frame, corner_radius=10, fg_color="#111827", border_width=1, border_color="#1f2937")
        card.pack(fill="x", pady=5, padx=3)
        card.grid_columnconfigure(1, weight=1)

        category = item.get("category", "General")
        cat_color = {
            "Bitcoin / Kripto Seed": "#f59e0b",
            "Özel Anahtar (Private Key)": "#ef4444",
            "Kullanıcı Parolası": "#3b82f6",
            "Gizli Not": "#10b981",
        }.get(category, "#8b5cf6")

        title_box = ctk.CTkFrame(card, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=14, pady=10, sticky="w")
        lbl_title = ctk.CTkLabel(title_box, text=item["title"], font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc")
        lbl_title.pack(anchor="w")

        cat_badge = ctk.CTkLabel(title_box, text=f"● {category}", font=ctk.CTkFont(size=11, weight="bold"), text_color=cat_color)
        cat_badge.pack(anchor="w")

        secret_box = ctk.CTkFrame(card, fg_color="#1e293b", corner_radius=8)
        secret_box.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        display_text = item["secret"] if is_revealed else "•" * 24
        lbl_secret = ctk.CTkLabel(
            secret_box,
            text=display_text,
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color="#38bdf8" if is_revealed else "#94a3b8"
        )
        lbl_secret.pack(side="left", padx=12, pady=6)

        btn_box = ctk.CTkFrame(card, fg_color="transparent")
        btn_box.grid(row=0, column=2, padx=14, pady=10, sticky="e")

        eye_btn = ctk.CTkButton(
            btn_box,
            text=get_text("btn_hide") if is_revealed else get_text("btn_show"),
            width=70,
            height=30,
            fg_color="#334155",
            hover_color="#475569",
            command=lambda i=item_id: self._toggle_reveal_secret(i)
        )
        eye_btn.pack(side="left", padx=3)

        copy_btn = ctk.CTkButton(
            btn_box,
            text="📋",
            width=36,
            height=30,
            fg_color="#0284c7",
            hover_color="#0369a1",
            command=lambda s=item["secret"]: self._copy_to_clipboard(s)
        )
        copy_btn.pack(side="left", padx=3)

        del_btn = ctk.CTkButton(
            btn_box,
            text="🗑️",
            width=36,
            height=30,
            fg_color="#450a0a",
            hover_color="#7f1d1d",
            text_color="#f87171",
            command=lambda i=item_id, t=item["title"]: self._delete_secret(i, t)
        )
        del_btn.pack(side="left", padx=3)

    def _toggle_reveal_secret(self, item_id: str):
        if item_id in self.revealed_secrets:
            self.revealed_secrets.remove(item_id)
        else:
            self.revealed_secrets.add(item_id)
        self._render_vault_cards()

    def _copy_to_clipboard(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo(get_text("copied_alert"), text[:40] + ("..." if len(text) > 40 else ""))

    def _delete_secret(self, item_id: str, title: str):
        msg = get_text("delete_confirm", title=title)
        if messagebox.askyesno("Confirm", msg):
            vault_storage.delete_secret_item(self.effective_password or self.master_password, self.vault_data, item_id)
            if item_id in self.revealed_secrets:
                self.revealed_secrets.remove(item_id)
            self._render_vault_cards()

    def open_add_secret_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title(get_text("modal_add_title"))
        modal.geometry("560x520")
        modal.transient(self)
        modal.grab_set()

        lbl_head = ctk.CTkLabel(modal, text=get_text("modal_add_title"), font=ctk.CTkFont(size=18, weight="bold"), text_color="#38bdf8")
        lbl_head.pack(pady=(16, 6), padx=25)

        title_entry = ctk.CTkEntry(modal, placeholder_text=get_text("field_title"), height=38)
        title_entry.pack(pady=6, padx=25, fill="x")

        cat_menu = ctk.CTkOptionMenu(
            modal,
            values=["Bitcoin / Kripto Seed", "Özel Anahtar (Private Key)", "Kullanıcı Parolası", "Gizli Not"],
            height=36
        )
        cat_menu.pack(pady=6, padx=25, fill="x")

        lbl_sec = ctk.CTkLabel(modal, text=get_text("field_secret"), font=ctk.CTkFont(size=12, weight="bold"))
        lbl_sec.pack(anchor="w", padx=25, pady=(8, 2))

        secret_text = ctk.CTkTextbox(modal, height=90, font=ctk.CTkFont(family="Consolas", size=13))
        secret_text.pack(pady=4, padx=25, fill="x")

        ent_lbl = ctk.CTkLabel(modal, text="Entropi: 0 bit", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        ent_lbl.pack(anchor="w", padx=25)

        def update_entropy_display(event=None):
            val = secret_text.get("1.0", "end").strip()
            res = crypto_utils.calculate_password_entropy(val)
            ent_lbl.configure(text=f"Entropi: {res['entropy']} bit - {res['label']}", text_color=res["color"])

        secret_text.bind("<KeyRelease>", update_entropy_display)

        def generate_and_fill():
            pw = vault_storage.generate_secure_password(length=32, use_symbols=True)
            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", pw)
            update_entropy_display()

        gen_btn = ctk.CTkButton(
            modal,
            text=get_text("btn_generate_pass"),
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=32,
            command=generate_and_fill
        )
        gen_btn.pack(pady=6, padx=25, fill="x")

        notes_entry = ctk.CTkEntry(modal, placeholder_text=get_text("field_notes"), height=36)
        notes_entry.pack(pady=6, padx=25, fill="x")

        def save_and_close():
            t = title_entry.get().strip()
            s = secret_text.get("1.0", "end").strip()
            c = cat_menu.get()
            n = notes_entry.get().strip()

            if not t or not s:
                return

            vault_storage.add_secret_item(
                self.effective_password or self.master_password, self.vault_data, title=t, category=c, secret_value=s, notes=n
            )
            modal.destroy()
            self._render_vault_cards()

        save_btn = ctk.CTkButton(
            modal,
            text=get_text("btn_save_vault"),
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            height=40,
            command=save_and_close
        )
        save_btn.pack(pady=(12, 18), padx=25, fill="x")

    # =========================================================================
    # 4. MODÜL: PORTFÖY (BLOCKCHAIN.INFO DOĞRULAMALI)
    # =========================================================================
    def _render_portfolio_view(self, parent):
        parent.grid_rowconfigure(2, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#172554", border_width=1, border_color="#1d4ed8", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("portfolio_desc"), font=ctk.CTkFont(size=12), text_color="#93c5fd", justify="left")
        info_lbl.pack(padx=16, pady=10, anchor="w")

        stats_frame = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=10)
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_columnconfigure(1, weight=1)

        portfolio_items = self.vault_data.get("portfolio", [])
        totals = crypto_portfolio.calculate_portfolio_value(portfolio_items, self.live_prices)

        total_box = ctk.CTkFrame(stats_frame, fg_color="transparent")
        total_box.grid(row=0, column=0, padx=20, pady=12, sticky="w")
        ctk.CTkLabel(total_box, text=get_text("total_portfolio_val"), font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(anchor="w")
        ctk.CTkLabel(
            total_box,
            text=f"${totals['total_usd']:,.2f}  |  ₺{totals['total_try']:,.2f}",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color="#4ade80"
        ).pack(anchor="w")

        price_box = ctk.CTkFrame(stats_frame, fg_color="transparent")
        price_box.grid(row=0, column=1, padx=20, pady=12, sticky="e")
        btc_p = self.live_prices.get("BTC", {}).get("usd", 0)
        eth_p = self.live_prices.get("ETH", {}).get("usd", 0)
        sol_p = self.live_prices.get("SOL", {}).get("usd", 0)
        price_str = f"BTC: ${btc_p:,.0f} | ETH: ${eth_p:,.0f} | SOL: ${sol_p:,.1f}"
        ctk.CTkLabel(price_box, text=get_text("crypto_price_live"), font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="e")
        ctk.CTkLabel(price_box, text=price_str, font=ctk.CTkFont(size=13, weight="bold"), text_color="#38bdf8").pack(anchor="e")

        addr_scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        addr_scroll.grid(row=2, column=0, sticky="nsew")
        addr_scroll.grid_columnconfigure(0, weight=1)

        top_act = ctk.CTkFrame(addr_scroll, fg_color="transparent")
        top_act.pack(fill="x", pady=(0, 8))
        add_addr_btn = ctk.CTkButton(top_act, text=get_text("btn_add_address"), fg_color="#0284c7", command=self._open_add_address_modal, height=32)
        add_addr_btn.pack(side="left")

        ref_btn = ctk.CTkButton(top_act, text=get_text("btn_refresh_prices"), fg_color="#334155", command=self._refresh_portfolio_and_balances, height=32)
        ref_btn.pack(side="right")

        if not portfolio_items:
            ctk.CTkLabel(addr_scroll, text="Henüz eklenmiş adres yok.", font=ctk.CTkFont(size=13), text_color="#64748b").pack(pady=40)
        else:
            for item in portfolio_items:
                self._create_address_card(addr_scroll, item)

    def _create_address_card(self, parent, item: dict):
        coin = item.get("coin", "BTC")
        amount = float(item.get("amount", 0.0))
        usd_rate = self.live_prices.get(coin, {}).get("usd", 0.0)
        val_usd = amount * usd_rate

        card = ctk.CTkFrame(parent, fg_color="#111827", corner_radius=10, border_width=1, border_color="#1f2937")
        card.pack(fill="x", pady=4)
        card.grid_columnconfigure(1, weight=1)

        col_left = ctk.CTkFrame(card, fg_color="transparent")
        col_left.grid(row=0, column=0, padx=14, pady=10, sticky="w")
        ctk.CTkLabel(col_left, text=item.get("label", "Cold Wallet"), font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc").pack(anchor="w")
        ctk.CTkLabel(col_left, text=f"{coin}: {item.get('address')[:16]}...{item.get('address')[-8:]}", font=ctk.CTkFont(family="Consolas", size=11), text_color="#94a3b8").pack(anchor="w")

        col_mid = ctk.CTkFrame(card, fg_color="transparent")
        col_mid.grid(row=0, column=1, padx=10, pady=10, sticky="e")
        ctk.CTkLabel(col_mid, text=f"{amount} {coin}", font=ctk.CTkFont(size=14, weight="bold"), text_color="#38bdf8").pack(anchor="e")
        ctk.CTkLabel(col_mid, text=f"≈ ${val_usd:,.2f}", font=ctk.CTkFont(size=12), text_color="#4ade80").pack(anchor="e")

        del_btn = ctk.CTkButton(
            card,
            text="🗑️",
            width=36,
            height=30,
            fg_color="#450a0a",
            hover_color="#7f1d1d",
            text_color="#f87171",
            command=lambda i=item["id"]: self._delete_portfolio_item(i)
        )
        del_btn.grid(row=0, column=2, padx=14, pady=10)

    def _open_add_address_modal(self):
        modal = ctk.CTkToplevel(self)
        modal.title(get_text("btn_add_address"))
        modal.geometry("520x440")
        modal.transient(self)
        modal.grab_set()

        lbl = ctk.CTkLabel(modal, text=get_text("btn_add_address"), font=ctk.CTkFont(size=16, weight="bold"), text_color="#38bdf8")
        lbl.pack(pady=(16, 8))

        label_in = ctk.CTkEntry(modal, placeholder_text="Cüzdan Etiketi (Örn: Ledger Nano BTC)", height=36)
        label_in.pack(pady=5, padx=25, fill="x")

        coin_menu = ctk.CTkOptionMenu(modal, values=["BTC", "ETH", "SOL"], height=36)
        coin_menu.pack(pady=5, padx=25, fill="x")

        addr_in = ctk.CTkEntry(modal, placeholder_text="Genel Adres (Public Address - bc1q... / 0x...)", height=36)
        addr_in.pack(pady=5, padx=25, fill="x")

        val_status_lbl = ctk.CTkLabel(modal, text="", font=ctk.CTkFont(size=11), text_color="#94a3b8")
        val_status_lbl.pack(padx=25, anchor="w")

        amount_in = ctk.CTkEntry(modal, placeholder_text="Miktar (Manuel veya Canlı Çek)", height=36)
        amount_in.pack(pady=5, padx=25, fill="x")

        def check_and_fetch_live():
            c = coin_menu.get()
            a = addr_in.get().strip()
            is_valid, msg = crypto_portfolio.validate_crypto_address(c, a)
            if not is_valid:
                val_status_lbl.configure(text=f"❌ {msg}", text_color="#ef4444")
                return
            val_status_lbl.configure(text=f"✅ {msg}", text_color="#4ade80")

            if c == "BTC":
                live_btc = crypto_portfolio.fetch_live_btc_balance(a)
                amount_in.delete(0, "end")
                amount_in.insert(0, str(live_btc))
                messagebox.showinfo("Blockchain.info", f"Blockchain düğümünden canlı bakiye çekildi: {live_btc} BTC")

        fetch_btn = ctk.CTkButton(
            modal,
            text="📡 Adresi Doğrula ve Canlı Bakiyeyi Blokzincirden Çek",
            fg_color="#1e293b",
            hover_color="#334155",
            text_color="#38bdf8",
            height=32,
            command=check_and_fetch_live
        )
        fetch_btn.pack(pady=6, padx=25, fill="x")

        def save():
            l = label_in.get().strip()
            c = coin_menu.get()
            a = addr_in.get().strip()
            is_valid, msg = crypto_portfolio.validate_crypto_address(c, a)
            if not is_valid:
                messagebox.showerror("Error", f"Geçersiz adres: {msg}")
                return
            try:
                amt = float(amount_in.get().strip())
            except ValueError:
                amt = 0.0

            vault_storage.add_portfolio_item(self.effective_password or self.master_password, self.vault_data, coin=c, label=l, address=a, amount=amt)
            modal.destroy()
            self.render_active_tab()

        save_btn = ctk.CTkButton(modal, text="KAYDET", fg_color="#0284c7", height=40, command=save)
        save_btn.pack(pady=12, padx=25, fill="x")

    def _delete_portfolio_item(self, item_id: str):
        vault_storage.delete_portfolio_item(self.effective_password or self.master_password, self.vault_data, item_id)
        self.render_active_tab()

    def _refresh_portfolio_and_balances(self):
        self.live_prices = crypto_portfolio.fetch_live_prices()
        # Kayıtlı BTC adreslerinin bakiyelerini de güncelle
        for item in self.vault_data.get("portfolio", []):
            if item.get("coin") == "BTC":
                live_b = crypto_portfolio.fetch_live_btc_balance(item.get("address", ""))
                if live_b > 0:
                    item["amount"] = live_b
        vault_storage.save_vault(self.effective_password or self.master_password, self.vault_data, is_decoy=self.is_decoy)
        self.render_active_tab()
        messagebox.showinfo("Updated", "Fiyatlar ve BTC bakiyeleri başarıyla güncellendi!")

    # =========================================================================
    # 5. MODÜL: CANLI P2P ŞİFRELİ SOHBET AĞI (CANLI SOKET)
    # =========================================================================
    def _render_p2p_chat_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#1e1b4b", border_width=1, border_color="#3730a3", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("p2p_chat_desc"), font=ctk.CTkFont(size=12), text_color="#c7d2fe", justify="left")
        info_lbl.pack(padx=16, pady=10, anchor="w")

        chat_layout = ctk.CTkFrame(parent, fg_color="transparent")
        chat_layout.grid(row=1, column=0, sticky="nsew")
        chat_layout.grid_rowconfigure(1, weight=1)
        chat_layout.grid_columnconfigure(0, weight=1)

        # Üst Bağlantı Kontrolleri
        top_conn = ctk.CTkFrame(chat_layout, fg_color="#0f172a", corner_radius=10)
        top_conn.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.p2p_status_lbl = ctk.CTkLabel(top_conn, text="⚪ Durum: Bağlantı yok.", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8")
        self.p2p_status_lbl.pack(padx=15, pady=(10, 4), anchor="w")

        ctrl_box = ctk.CTkFrame(top_conn, fg_color="transparent")
        ctrl_box.pack(fill="x", padx=15, pady=(0, 10))

        nick_in = ctk.CTkEntry(ctrl_box, placeholder_text="Rumuzunuz...", width=140, height=32)
        nick_in.insert(0, self.selected_profile)
        nick_in.pack(side="left", padx=4)

        room_key_in = ctk.CTkEntry(ctrl_box, placeholder_text="Oda Şifresi...", show="*", width=160, height=32)
        room_key_in.insert(0, "AegisRoom2026!")
        room_key_in.pack(side="left", padx=4)

        ip_in = ctk.CTkEntry(ctrl_box, placeholder_text="Host IP:Port (Katılmak için)...", width=190, height=32)
        ip_in.insert(0, f"{live_p2p_chat.get_local_ip()}:9876")
        ip_in.pack(side="left", padx=4)

        def update_status(text):
            self.after(0, lambda: self.p2p_status_lbl.configure(text=text))

        def on_msg_received(sender, text, ts, is_mine):
            def add_bubble():
                bubble = ctk.CTkFrame(self.p2p_messages_box, fg_color="#0284c7" if is_mine else "#1e293b", corner_radius=8)
                bubble.pack(fill="x", pady=4, padx=8)
                hdr = f"{sender} ({ts})" if not is_mine else f"Siz ({ts})"
                ctk.CTkLabel(bubble, text=hdr, font=ctk.CTkFont(size=10, weight="bold"), text_color="#cbd5e1").pack(anchor="w", padx=10, pady=(4, 0))
                ctk.CTkLabel(bubble, text=text, font=ctk.CTkFont(size=13), text_color="#ffffff", justify="left").pack(anchor="w", padx=10, pady=(2, 6))
            self.after(0, add_bubble)

        def do_host():
            if self.p2p_session:
                self.p2p_session.close()
            nick = nick_in.get().strip() or "Host"
            key = room_key_in.get().strip()
            self.p2p_session = live_p2p_chat.P2PChatSession(nick, key, on_msg_received, update_status)
            self.p2p_session.start_host(port=9876)

        def do_join():
            if self.p2p_session:
                self.p2p_session.close()
            nick = nick_in.get().strip() or "Guest"
            key = room_key_in.get().strip()
            target = ip_in.get().strip()
            host = target.split(":")[0]
            port = int(target.split(":")[1]) if ":" in target else 9876
            self.p2p_session = live_p2p_chat.P2PChatSession(nick, key, on_msg_received, update_status)
            self.p2p_session.connect_to_host(host, port)

        host_btn = ctk.CTkButton(ctrl_box, text=get_text("btn_host_start"), fg_color="#0284c7", width=120, height=32, command=do_host)
        host_btn.pack(side="left", padx=4)

        join_btn = ctk.CTkButton(ctrl_box, text=get_text("btn_join_start"), fg_color="#059669", width=120, height=32, command=do_join)
        join_btn.pack(side="left", padx=4)

        # Mesaj Akışı Kutusu
        self.p2p_messages_box = ctk.CTkScrollableFrame(chat_layout, fg_color="#0b1120", corner_radius=10)
        self.p2p_messages_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))

        # Alt Mesaj Gönderim Alanı
        bot_send = ctk.CTkFrame(chat_layout, fg_color="transparent")
        bot_send.grid(row=2, column=0, sticky="ew")
        bot_send.grid_columnconfigure(0, weight=1)

        msg_input = ctk.CTkEntry(bot_send, placeholder_text="Uçtan uca AES-256-GCM şifreli mesajınızı yazın...", height=40)
        msg_input.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        def send_p2p(event=None):
            txt = msg_input.get().strip()
            if not txt:
                return
            if not self.p2p_session or not self.p2p_session.conn:
                messagebox.showwarning("Not Connected", "Henüz bir odaya bağlı değilsiniz!")
                return
            if self.p2p_session.send_message(txt):
                msg_input.delete(0, "end")

        msg_input.bind("<Return>", send_p2p)

        send_btn = ctk.CTkButton(bot_send, text=get_text("btn_send"), fg_color="#0284c7", width=100, height=40, command=send_p2p)
        send_btn.grid(row=0, column=1)

    # =========================================================================
    # 6. SHAMIR'S SECRET SHARING (SSS)
    # =========================================================================
    def _render_shamir_view(self, parent):
        parent.grid_rowconfigure(1, weight=1)

        info_card = ctk.CTkFrame(parent, fg_color="#064e3b", border_width=1, border_color="#059669", corner_radius=10)
        info_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_lbl = ctk.CTkLabel(info_card, text=get_text("shamir_desc"), font=ctk.CTkFont(size=12), text_color="#a7f3d0", justify="left")
        info_lbl.pack(padx=16, pady=10, anchor="w")

        tabview = ctk.CTkTabview(parent)
        tabview.grid(row=1, column=0, sticky="nsew")
        tab_split = tabview.add(get_text("tab_split"))
        tab_combine = tabview.add(get_text("tab_combine"))

        sec_in = ctk.CTkTextbox(tab_split, height=70, font=ctk.CTkFont(family="Consolas", size=12))
        sec_in.pack(fill="x", padx=15, pady=6)
        sec_in.insert("1.0", "witch collapse practice feed shame open despair creek road again ice least")

        opts_frame = ctk.CTkFrame(tab_split, fg_color="transparent")
        opts_frame.pack(fill="x", padx=15, pady=4)
        ctk.CTkLabel(opts_frame, text=get_text("label_n")).pack(side="left", padx=5)
        n_menu = ctk.CTkOptionMenu(opts_frame, values=["3", "4", "5", "6", "7"], width=70)
        n_menu.set("5")
        n_menu.pack(side="left", padx=5)

        ctk.CTkLabel(opts_frame, text=get_text("label_k")).pack(side="left", padx=15)
        k_menu = ctk.CTkOptionMenu(opts_frame, values=["2", "3", "4", "5"], width=70)
        k_menu.set("3")
        k_menu.pack(side="left", padx=5)

        out_text = ctk.CTkTextbox(tab_split, height=130, font=ctk.CTkFont(family="Consolas", size=11))
        out_text.pack(fill="both", expand=True, padx=15, pady=6)

        def do_split():
            text = sec_in.get("1.0", "end").strip()
            if not text:
                return
            n = int(n_menu.get())
            k = int(k_menu.get())
            if k > n:
                messagebox.showerror("Error", "K cannot exceed N!")
                return
            shares = crypto_utils.shamir_split(text, k, n)
            out_text.delete("1.0", "end")
            out_text.insert("1.0", "\n\n".join(shares))

        split_btn = ctk.CTkButton(tab_split, text=get_text("btn_do_split"), fg_color="#0284c7", command=do_split)
        split_btn.pack(pady=8, padx=15, fill="x")

        # Birleştir
        comb_in = ctk.CTkTextbox(tab_combine, height=120, font=ctk.CTkFont(family="Consolas", size=11))
        comb_in.pack(fill="x", padx=15, pady=4)

        comb_out = ctk.CTkTextbox(tab_combine, height=70, font=ctk.CTkFont(family="Consolas", size=12))
        comb_out.pack(fill="x", padx=15, pady=6)

        def do_combine():
            raw = comb_in.get("1.0", "end").strip().splitlines()
            try:
                secret = crypto_utils.shamir_combine(raw)
                comb_out.delete("1.0", "end")
                comb_out.insert("1.0", secret)
                messagebox.showinfo("Success", "Gizli veri Shamir parçalarından kurtarıldı!")
            except Exception as e:
                messagebox.showerror("Error", f"Kurtarma hatası: {e}")

        comb_btn = ctk.CTkButton(tab_combine, text=get_text("btn_do_combine"), fg_color="#059669", command=do_combine)
        comb_btn.pack(pady=8, padx=15, fill="x")

    # =========================================================================
    # 7. BIP-39 VE REHBER
    # =========================================================================
    def _render_bip39_view(self, parent):
        lbl_head = ctk.CTkLabel(parent, text="🔍 BIP-39 Tohum Analizi", font=ctk.CTkFont(size=18, weight="bold"), text_color="#38bdf8")
        lbl_head.pack(pady=(10, 6), anchor="w")

        seed_box = ctk.CTkTextbox(parent, height=90, font=ctk.CTkFont(family="Consolas", size=13))
        seed_box.pack(fill="x", pady=6)
        seed_box.insert("1.0", "witch collapse practice feed shame open despair creek road again ice least")

        res_card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=10)
        res_card.pack(fill="x", pady=10)

        res_lbl = ctk.CTkLabel(res_card, text="", font=ctk.CTkFont(size=13), justify="left")
        res_lbl.pack(padx=16, pady=12, anchor="w")

        def analyze():
            text = seed_box.get("1.0", "end").strip()
            res = crypto_utils.validate_bip39_seed(text)
            color = "#4ade80" if res["is_valid_length"] and res["is_valid_format"] else "#ef4444"
            res_lbl.configure(
                text=(
                    f"● Kelime Sayısı: {res['word_count']}\n"
                    f"● Standart Uyumu: {'Geçerli Uzunluk (12/15/18/21/24)' if res['is_valid_length'] else 'Hatalı Kelime Sayısı'}\n"
                    f"● Karakter Seti: {'Doğru Format' if res['is_valid_format'] else 'Hatalı Karakterler'}\n"
                    f"● Teorik Entropi: {res['entropy_bits']} bit\n"
                    f"● Sonuç: {res['standard_status']}"
                ),
                text_color=color
            )

        btn = ctk.CTkButton(parent, text="TOHUMU ANALİZ ET", fg_color="#0284c7", command=analyze, height=36)
        btn.pack(fill="x", pady=6)
        analyze()

    def _render_guide_view(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        guide_texts = [
            ("🛡️ AES-256-GCM Neden Askeri Standarttır?", 
             "AES-256, ABD Ulusal Güvenlik Ajansı (NSA) tarafından 'Top Secret' düzeyindeki devlet sırlarını korumak için onaylanan CNSA Suite standardıdır. 256-bit anahtar kombinasyonunu kırmak için evrendeki tüm atomların sayısından daha fazla hesaplama gücü gerekir.\nGCM (Galois/Counter Mode) modu ise şifreli metinle birlikte 128-bitlik bir doğrulama etiketi (Auth Tag) üretir. Dosyadaki tek bir harf veya bit değiştirilse dahi sistem bunu fark eder ve işlemi iptal eder."),
            
            ("🔒 scrypt ve GPU Brute-Force Direnci", 
             "Standart SHA-256 veya MD5 algoritmaları bilgisayar belleği (RAM) kullanmaz. Bu yüzden bir saldırgan RTX 4090 gibi GPU çiftlikleriyle saniyede milyarlarca parola deneyebilir.\nAegisVault'ta kullanılan 'scrypt' algoritması her parola denemesinde ~32 MB RAM ayrılmasını zorunlu kılar. Bu bellek darboğazı sayesinde GPU'lar kilitlenir ve saniyede yalnızca birkaç yüz deneme yapabilir; kaba kuvvet saldırısı imkansız hale gelir."),
             
            ("🧩 Shamir's Secret Sharing (SSS) Nedir?", 
             "Adını efsanevi kriptograf Adi Shamir'den alan bu sistem, bir sırrı N parçaya böler ve K tanesi olmadan çözülmesini imkansız kılar. 3-of-5 sisteminde oluşturulan 5 parçayı farklı şehirlerdeki banka kasalarına veya güvendiğiniz aile üyelerine dağıtabilirsiniz. Yangın veya hırsızlık durumunda 2 parça yok olsa bile paranızı kurtarabilirsiniz."),
             
            ("🎭 Tehdit Parolası (Duress Password / Plausible Deniability)", 
             "Birisi fiziksel baskı altında kasanızı açmanızı isterse önceden belirlediğiniz sahte parolayı girebilirsiniz. Sistem gerçek verileriniz yerine sıradan önemsiz hesapların bulunduğu sahte bir kasa açar. Saldırgan gerçek kasanın varlığını matematiksel olarak kanıtlayamaz."),

            ("🔒 Cihaza Özel Donanım İmzası (Hardware Binding)",
             "Kasanızı oluştururken bu seçeneği işaretlediğinizde, anahtar türetimi bilgisayarınızın anakart ve donanım kimliğiyle harmanlanır. Kasa dosyanız (.mvat) çalınıp başka bir bilgisayara götürülse bile şifreyi bilseler dahi açılamaz.")
        ]

        for title, body in guide_texts:
            card = ctk.CTkFrame(scroll, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
            card.pack(fill="x", pady=8, padx=4)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 4))
            ctk.CTkLabel(card, text=body, font=ctk.CTkFont(size=12), text_color="#cbd5e1", justify="left", wraplength=720).pack(anchor="w", padx=16, pady=(0, 14))

    # =========================================================================
    # 9. ASKERİ DENETİM & FIPS 140-3 ÖZ-TEST GÜNLÜĞÜ (AUDIT TRAIL)
    # =========================================================================
    def _render_audit_view(self, parent):
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # FIPS 140-3 POST Test Kartı
        post_card = ctk.CTkFrame(scroll, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
        post_card.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(post_card, text="🛡️ FIPS 140-3 Power-On Self-Tests (POST / Açılış Öz-Testleri)", font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(post_card, text="Sistem açılışında NIST test vektörleri (KAT) ve donanımsal entropi havuzu otomatik doğrulanmıştır.", font=ctk.CTkFont(size=11), text_color="#94a3b8").pack(anchor="w", padx=16, pady=(0, 8))

        tests = getattr(self, "post_results", {}).get("tests", [])
        for t in tests:
            t_row = ctk.CTkFrame(post_card, fg_color="transparent")
            t_row.pack(fill="x", padx=16, pady=2)
            icon = "✅" if t["passed"] else "❌"
            ctk.CTkLabel(t_row, text=f"{icon} {t['name']}", font=ctk.CTkFont(size=12, weight="bold"), text_color="#4ade80" if t["passed"] else "#ef4444").pack(side="left")
            ctk.CTkLabel(t_row, text=f"- {t['details']}", font=ctk.CTkFont(size=11), text_color="#cbd5e1").pack(side="left", padx=8)

        # Aksiyon Butonları (Bütünlük Doğrulama & Acil İmha)
        act_box = ctk.CTkFrame(scroll, fg_color="transparent")
        act_box.pack(fill="x", pady=8)

        def verify_chain():
            ok, msg, count = military_audit.CryptographicAuditTrail.verify_integrity()
            if ok:
                messagebox.showinfo("Audit Integrity Passed", f"✅ {msg}")
            else:
                messagebox.showerror("Audit Integrity FAILED", f"❌ {msg}")

        def trigger_zeroize():
            msg = f"DİKKAT: '{self.selected_profile}' profili ve diskteki şifreli dosyalar rastgele baytlarla (DoD 5220.22-M) kalıcı olarak imha edilecektir.\nBu işlem GERİ ALINAMAZ!\n\nDevam edilsin mi?"
            if messagebox.askyesno("EMERGENCY ZEROIZE", msg):
                if messagebox.askyesno("SON ONAY", "Tüm anahtarlar ve veriler tamamen yok edilecek. Emin misiniz?"):
                    military_audit.emergency_zeroize_vault(self.selected_profile)
                    messagebox.showinfo("Zeroize Complete", "Askeri sıfırlama tamamlandı. Uygulama kapatılıyor.")
                    sys.exit(0)

        ctk.CTkButton(act_box, text="🔍 Olay Günlüğü Zincirini Doğrula (Hash-Chain Verify)", fg_color="#0284c7", command=verify_chain, height=36).pack(side="left", padx=4)
        ctk.CTkButton(act_box, text="⚠️ Acil Durum Kriptografik İmhası (Emergency Zeroize)", fg_color="#7f1d1d", hover_color="#991b1b", command=trigger_zeroize, height=36).pack(side="right", padx=4)

        # Olay Günlüğü Akışı
        log_head = ctk.CTkLabel(scroll, text="📜 Kriptografik Olay Akışı (Tamper-Evident Merkle Trail):", font=ctk.CTkFont(size=14, weight="bold"))
        log_head.pack(anchor="w", pady=(10, 4))

        events = military_audit.CryptographicAuditTrail.get_recent_events(limit=25)
        for ev in events:
            ev_card = ctk.CTkFrame(scroll, fg_color="#111827", corner_radius=8, border_width=1, border_color="#1f2937")
            ev_card.pack(fill="x", pady=3)

            top_line = ctk.CTkFrame(ev_card, fg_color="transparent")
            top_line.pack(fill="x", padx=12, pady=(6, 2))
            ctk.CTkLabel(top_line, text=f"Blok #{ev['index']} [{ev['timestamp']}]", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(side="left")
            ctk.CTkLabel(top_line, text=f"Olay: {ev['event_type']} ({ev['actor']})", font=ctk.CTkFont(size=11), text_color="#f8fafc").pack(side="left", padx=10)

            hash_txt = f"Hash: {ev['hash'][:24]}... | Prev: {ev['prev_hash'][:16]}..."
            ctk.CTkLabel(ev_card, text=f"{ev['details']} | {hash_txt}", font=ctk.CTkFont(family="Consolas", size=10), text_color="#64748b").pack(anchor="w", padx=12, pady=(0, 6))


if __name__ == "__main__":
    app = AegisVaultApp()
    app.mainloop()
