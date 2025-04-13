import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import json
import socket
import webbrowser
from datetime import datetime
import pyperclip
import os
import io
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import folium
from folium.plugins import MarkerCluster
import ipaddress
from PIL import Image, ImageTk
import threading
import time

class IPGeoLocatorBeta:
    def __init__(self, root):
        self.root = root
        self.root.title("IP GeoLocator Pro BETA")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configuración inicial
        self.setup_config()
        
        # Interfaz
        self.create_widgets()
        
        # Iniciar con IP pública
        self.get_public_ip()

    def setup_config(self):
        """Configuración inicial de la aplicación"""
        self.colors = {
            "primary": "#2c3e50",
            "secondary": "#3498db",
            "accent": "#e74c3c",
            "bg_light": "#ecf0f1",
            "text_dark": "#2c3e50",
            "text_light": "#ffffff",
            "success": "#27ae60",
            "warning": "#f39c12",
            "error": "#e74c3c"
        }
        
        # Servicios de geolocalización con pesos para prioridad
        self.services = {
            "ip-api.com": {
                "url": "http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                "weight": 1.0,
                "timeout": 8
            },
            "ipapi.co": {
                "url": "https://ipapi.co/{ip}/json/",
                "weight": 0.9,
                "timeout": 10
            },
            "ipwhois.io": {
                "url": "http://ipwhois.app/json/{ip}",
                "weight": 0.8,
                "timeout": 8
            },
            "ipgeolocation.io": {
                "url": "https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip={ip}",
                "weight": 0.7,
                "timeout": 8
            }
        }
        
        # Historial
        self.history = []
        self.history_file = "history.json"
        self.load_history()
        
        # Cache de resultados
        self.cache = {}
        self.cache_file = "cache.json"
        self.load_cache()
        
        # Configuración de mapa
        self.map_zoom = 10
        self.map_tiles = "OpenStreetMap"
        
        # Estado de la aplicación
        self.search_in_progress = False

    def create_widgets(self):
        """Crea la interfaz gráfica"""
        self.setup_styles()
        
        # Frame principal
        self.main_frame = ttk.Frame(self.root, padding=(15, 15, 15, 15))
        self.main_frame.pack(fill="both", expand=True)
        
        # Cabecera
        self.create_header()
        
        # Panel de búsqueda
        self.create_search_panel()
        
        # Panel de resultados
        self.create_results_panel()
        
        # Barra de estado
        self.create_status_bar()

    def setup_styles(self):
        """Configura los estilos visuales"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("TFrame", background=self.colors["bg_light"])
        style.configure("TButton", background=self.colors["secondary"], 
                      foreground=self.colors["text_light"],
                      font=("Segoe UI", 10, "bold"), padding=8)
        style.map("TButton", 
                 background=[("active", self.colors["accent"]), 
                            ("disabled", "#cccccc")])
        style.configure("TLabel", background=self.colors["bg_light"], 
                       foreground=self.colors["text_dark"],
                       font=("Segoe UI", 11))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"),
                       foreground=self.colors["primary"])
        style.configure("TEntry", font=("Segoe UI", 11), padding=5)
        style.configure("TCombobox", font=("Segoe UI", 11), padding=5)
        style.configure("Status.TLabel", font=("Segoe UI", 9), relief="sunken")

    def create_header(self):
        """Crea la cabecera de la aplicación"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="IP GEOLOCATOR PRO BETA", 
                              style="Header.TLabel")
        title_label.pack(side="left")
        
        # Menú de herramientas
        tools_frame = ttk.Frame(header_frame)
        tools_frame.pack(side="right")
        
        ttk.Button(tools_frame, text="Config", command=self.show_settings).pack(side="left", padx=5)
        ttk.Button(tools_frame, text="Ayuda", command=self.show_help).pack(side="left", padx=5)
        ttk.Button(tools_frame, text="Acerca de", command=self.show_about).pack(side="left", padx=5)

    def create_search_panel(self):
        """Crea el panel de búsqueda"""
        search_frame = ttk.LabelFrame(self.main_frame, text="Buscar IP o Dominio", padding=10)
        search_frame.pack(fill="x", pady=(0, 10))
        
        # Entrada de búsqueda
        ttk.Label(search_frame, text="Dirección IP o Dominio:").pack(side="left")
        
        self.ip_entry = ttk.Entry(search_frame, width=40)
        self.ip_entry.pack(side="left", padx=10)
        self.ip_entry.bind("<Return>", lambda e: self.locate_ip())
        
        # Botones de acción
        btn_frame = ttk.Frame(search_frame)
        btn_frame.pack(side="right")
        
        ttk.Button(btn_frame, text="Buscar", command=self.locate_ip).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Mi IP", command=self.get_public_ip).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Limpiar", command=self.clear_fields).pack(side="left", padx=5)

    def create_results_panel(self):
        """Crea el panel de resultados con pestañas"""
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Pestaña de información básica
        self.create_info_tab()
        
        # Pestaña de mapa
        self.create_map_tab()
        
        # Pestaña de datos técnicos
        self.create_tech_tab()
        
        # Pestaña de gráficos
        self.create_charts_tab()
        
        # Pestaña de historial
        self.create_history_tab()

    def create_info_tab(self):
        """Crea la pestaña de información básica"""
        info_frame = ttk.Frame(self.notebook)
        self.notebook.add(info_frame, text="Información")
        
        # Información resumida
        summary_frame = ttk.LabelFrame(info_frame, text="Resumen", padding=10)
        summary_frame.pack(fill="x", pady=5)
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, height=8,
                                                    font=("Consolas", 10))
        self.summary_text.pack(fill="both", expand=True)
        
        # Información extendida
        details_frame = ttk.LabelFrame(info_frame, text="Detalles", padding=10)
        details_frame.pack(fill="both", expand=True)
        
        self.details_tree = ttk.Treeview(details_frame, columns=("property", "value"), show="headings")
        self.details_tree.heading("property", text="Propiedad")
        self.details_tree.heading("value", text="Valor")
        self.details_tree.column("property", width=150)
        self.details_tree.column("value", width=400)
        
        scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.details_tree.pack(fill="both", expand=True)

    def create_map_tab(self):
        """Crea la pestaña de mapa"""
        self.map_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.map_frame, text="Mapa")
        
        # Controles del mapa
        controls_frame = ttk.Frame(self.map_frame)
        controls_frame.pack(fill="x", pady=5)
        
        ttk.Button(controls_frame, text="Actualizar Mapa", command=self.update_map).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Abrir en Navegador", command=self.open_map_in_browser).pack(side="left", padx=5)
        
        # Contenedor del mapa
        self.map_container = ttk.Frame(self.map_frame)
        self.map_container.pack(fill="both", expand=True)
        
        # Label temporal hasta que se cargue el mapa
        self.map_label = ttk.Label(self.map_container, text="El mapa se cargará con los resultados...",
                                  font=("Segoe UI", 12))
        self.map_label.pack(fill="both", expand=True)

    def create_tech_tab(self):
        """Crea la pestaña de datos técnicos"""
        tech_frame = ttk.Frame(self.notebook)
        self.notebook.add(tech_frame, text="Datos Técnicos")
        
        self.tech_text = scrolledtext.ScrolledText(tech_frame, wrap=tk.WORD,
                                                font=("Consolas", 10))
        self.tech_text.pack(fill="both", expand=True)

    def create_charts_tab(self):
        """Crea la pestaña de gráficos"""
        self.charts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.charts_frame, text="Gráficos")
        
        # Aquí se agregarán los gráficos dinámicamente

    def create_history_tab(self):
        """Crea la pestaña de historial"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="Historial")
        
        # Controles del historial
        controls_frame = ttk.Frame(history_frame)
        controls_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(controls_frame, text="Actualizar", command=self.update_history_view).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Limpiar Historial", command=self.clear_history).pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Exportar a JSON", command=self.export_history).pack(side="left", padx=5)
        
        # Búsqueda en historial
        search_frame = ttk.Frame(controls_frame)
        search_frame.pack(side="right")
        
        ttk.Label(search_frame, text="Buscar:").pack(side="left")
        self.history_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.history_search_var, width=20)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self.update_history_view())
        
        # Treeview para el historial
        history_tree_frame = ttk.Frame(history_frame)
        history_tree_frame.pack(fill="both", expand=True)
        
        columns = ("timestamp", "ip", "country", "city", "isp")
        self.history_tree = ttk.Treeview(history_tree_frame, columns=columns, show="headings")
        
        # Configurar columnas
        self.history_tree.heading("timestamp", text="Fecha/Hora")
        self.history_tree.heading("ip", text="IP")
        self.history_tree.heading("country", text="País")
        self.history_tree.heading("city", text="Ciudad")
        self.history_tree.heading("isp", text="ISP")
        
        self.history_tree.column("timestamp", width=150)
        self.history_tree.column("ip", width=120)
        self.history_tree.column("country", width=150)
        self.history_tree.column("city", width=150)
        self.history_tree.column("isp", width=200)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(history_tree_frame, orient="vertical", 
                                command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.history_tree.pack(fill="both", expand=True)
        
        # Doble click para ver detalles
        self.history_tree.bind("<Double-1>", self.show_history_details)
        
        # Actualizar vista
        self.update_history_view()

    def create_status_bar(self):
        """Crea la barra de estado"""
        self.status_var = tk.StringVar(value="Listo para buscar direcciones IP")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, 
                             relief="sunken", anchor="w", style="Status.TLabel")
        status_bar.pack(fill="x", side="bottom", pady=(10, 0))

    def get_public_ip(self):
        """Obtiene la IP pública del usuario"""
        try:
            self.status_var.set("Obteniendo IP pública...")
            self.root.update()
            
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            if response.status_code == 200:
                ip = response.json().get("ip", "")
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, ip)
                self.locate_ip()
            else:
                messagebox.showerror("Error", "No se pudo obtener la IP pública")
                self.status_var.set("Error al obtener IP pública")
        except Exception as e:
            messagebox.showerror("Error", f"Error al obtener IP pública: {str(e)}")
            self.status_var.set("Error en la conexión")

    def locate_ip(self):
        """Realiza la geolocalización de la IP"""
        if self.search_in_progress:
            return
            
        ip_or_domain = self.ip_entry.get().strip()
        if not ip_or_domain:
            messagebox.showwarning("Advertencia", "Ingresa una dirección IP o dominio")
            return
        
        # Verificar caché primero
        if ip_or_domain in self.cache:
            cached_data = self.cache[ip_or_domain]
            if time.time() - cached_data["timestamp"] < 3600:  # 1 hora de cache
                self.display_results(ip_or_domain, cached_data["data"])
                self.status_var.set(f"Resultados en caché para {ip_or_domain}")
                return
        
        try:
            self.search_in_progress = True
            self.status_var.set(f"Buscando información para {ip_or_domain}...")
            self.root.update()
            
            # Resolver dominio a IP si es necesario
            if not self.is_valid_ip(ip_or_domain):
                try:
                    ip_or_domain = socket.gethostbyname(ip_or_domain)
                    self.ip_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, ip_or_domain)
                except socket.gaierror:
                    messagebox.showerror("Error", "Dominio no válido o no resuelto")
                    self.status_var.set("Error en la resolución del dominio")
                    self.search_in_progress = False
                    return
            
            # Verificar si es una IP válida
            if not self.is_valid_ip(ip_or_domain):
                messagebox.showerror("Error", "Dirección IP no válida")
                self.status_var.set("Dirección IP no válida")
                self.search_in_progress = False
                return
            
            # Ejecutar en un hilo para no bloquear la interfaz
            threading.Thread(target=self.perform_ip_lookup, args=(ip_or_domain,), daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al geolocalizar IP: {str(e)}")
            self.status_var.set("Error en la búsqueda")
            self.search_in_progress = False

    def perform_ip_lookup(self, ip):
        """Realiza la búsqueda de la IP en los servicios"""
        try:
            all_data = {}
            threads = []
            results = {}
            
            # Función para obtener datos de un servicio
            def fetch_service_data(service_name, service_config, ip_addr, result_dict):
                try:
                    url = service_config["url"].format(ip=ip_addr)
                    response = requests.get(url, timeout=service_config["timeout"])
                    if response.status_code == 200:
                        data = response.json()
                        result_dict[service_name] = {
                            "data": data,
                            "weight": service_config["weight"]
                        }
                except Exception as e:
                    print(f"Error con {service_name}: {str(e)}")
            
            # Crear hilos para cada servicio
            for service_name, service_config in self.services.items():
                thread = threading.Thread(
                    target=fetch_service_data,
                    args=(service_name, service_config, ip, results),
                    daemon=True
                )
                threads.append(thread)
                thread.start()
            
            # Esperar a que todos los hilos terminen o timeout general
            timeout = max(s["timeout"] for s in self.services.values()) + 2
            start_time = time.time()
            
            for thread in threads:
                remaining_time = max(0, timeout - (time.time() - start_time))
                thread.join(timeout=remaining_time)
                if thread.is_alive():
                    print(f"Timeout para {thread.name}")
            
            # Procesar resultados exitosos
            for service_name, result in results.items():
                all_data[service_name] = result["data"]
            
            if not all_data:
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", "No se pudo obtener información de ningún servicio"))
                self.status_var.set("Error en los servicios")
                self.search_in_progress = False
                return
            
            # Combinar datos con pesos
            combined_data = self.combine_data_with_weights(all_data)
            
            # Actualizar caché
            self.cache[ip] = {
                "data": combined_data,
                "timestamp": time.time()
            }
            self.save_cache()
            
            # Mostrar resultados en el hilo principal
            self.root.after(0, lambda: self.display_results(ip, combined_data))
            self.root.after(0, lambda: self.add_to_history(ip, combined_data))
            self.root.after(0, lambda: self.status_var.set(
                f"Información obtenida para {ip}"))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"Error en la búsqueda: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Error en la búsqueda"))
        
        finally:
            self.search_in_progress = False

    def is_valid_ip(self, ip_str):
        """Verifica si la cadena es una IP válida"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def combine_data_with_weights(self, all_data):
        """Combina datos de múltiples servicios considerando pesos"""
        combined = {
            "ip": "",
            "country": "",
            "country_code": "",
            "region": "",
            "city": "",
            "zip": "",
            "latitude": None,
            "longitude": None,
            "timezone": "",
            "isp": "",
            "org": "",
            "asn": "",
            "asname": "",
            "reverse": "",
            "proxy": None,
            "hosting": None,
            "mobile": None,
            "continent": "",
            "continent_code": "",
            "currency": "",
            "services": {},
            "confidence": 0
        }
        
        total_weight = 0
        lat_sum = 0
        lon_sum = 0
        lat_count = 0
        lon_count = 0
        
        # Recopilar datos de todos los servicios
        for service, data in all_data.items():
            weight = self.services[service]["weight"]
            combined["services"][service] = data
            combined["confidence"] += weight
            
            # Campos comunes con pesos
            if data.get("country") and (not combined["country"] or weight > 0.9):
                combined["country"] = data.get("country")
            
            if data.get("country_code") and (not combined["country_code"] or weight > 0.9):
                combined["country_code"] = data.get("country_code")
            
            if data.get("region") and (not combined["region"] or weight > 0.9):
                combined["region"] = data.get("region")
            elif data.get("regionName") and (not combined["region"] or weight > 0.9):
                combined["region"] = data.get("regionName")
            
            if data.get("city") and (not combined["city"] or weight > 0.9):
                combined["city"] = data.get("city")
            
            if data.get("zip") and (not combined["zip"] or weight > 0.9):
                combined["zip"] = data.get("zip")
            elif data.get("postal") and (not combined["zip"] or weight > 0.9):
                combined["zip"] = data.get("postal")
            
            if data.get("timezone") and (not combined["timezone"] or weight > 0.9):
                combined["timezone"] = data.get("timezone")
            
            if data.get("isp") and (not combined["isp"] or weight > 0.9):
                combined["isp"] = data.get("isp")
            
            if data.get("org") and (not combined["org"] or weight > 0.9):
                combined["org"] = data.get("org")
            
            if data.get("asn") and (not combined["asn"] or weight > 0.9):
                combined["asn"] = data.get("asn")
            
            if data.get("asname") and (not combined["asname"] or weight > 0.9):
                combined["asname"] = data.get("asname")
            
            if data.get("reverse") and (not combined["reverse"] or weight > 0.9):
                combined["reverse"] = data.get("reverse")
            
            if data.get("proxy") is not None and combined["proxy"] is None:
                combined["proxy"] = data.get("proxy")
            
            if data.get("hosting") is not None and combined["hosting"] is None:
                combined["hosting"] = data.get("hosting")
            
            if data.get("mobile") is not None and combined["mobile"] is None:
                combined["mobile"] = data.get("mobile")
            
            if data.get("continent") and (not combined["continent"] or weight > 0.9):
                combined["continent"] = data.get("continent")
            
            if data.get("continentCode") and (not combined["continent_code"] or weight > 0.9):
                combined["continent_code"] = data.get("continentCode")
            
            if data.get("currency") and (not combined["currency"] or weight > 0.9):
                combined["currency"] = data.get("currency")
            
            # Coordenadas (promedio ponderado)
            if data.get("lat") and data.get("lon"):
                try:
                    lat = float(data.get("lat"))
                    lon = float(data.get("lon"))
                    lat_sum += lat * weight
                    lon_sum += lon * weight
                    lat_count += weight
                    lon_count += weight
                except (ValueError, TypeError):
                    pass
            elif data.get("latitude") and data.get("longitude"):
                try:
                    lat = float(data.get("latitude"))
                    lon = float(data.get("longitude"))
                    lat_sum += lat * weight
                    lon_sum += lon * weight
                    lat_count += weight
                    lon_count += weight
                except (ValueError, TypeError):
                    pass
        
        # Calcular promedio ponderado de coordenadas
        if lat_count > 0 and lon_count > 0:
            combined["latitude"] = lat_sum / lat_count
            combined["longitude"] = lon_sum / lon_count
        
        # IP (de cualquier servicio)
        for data in all_data.values():
            if data.get("ip"):
                combined["ip"] = data.get("ip")
                break
            elif data.get("query"):
                combined["ip"] = data.get("query")
                break
        
        # Calcular confianza (0-100%)
        combined["confidence"] = min(100, int((combined["confidence"] / sum(
            s["weight"] for s in self.services.values())) * 100)
        
        return combined

    def display_results(self, ip, data):
        """Muestra los resultados en la interfaz"""
        # Información básica
        basic_info = f"""IP: {data['ip']}
Confianza: {data['confidence']}%
País: {data['country']} ({data['country_code']})
Continente: {data['continent']} ({data['continent_code']})
Región: {data['region']}
Ciudad: {data['city']} (Código Postal: {data['zip']})
Coordenadas: {data['latitude']}, {data['longitude']}
Zona Horaria: {data['timezone']}
ISP: {data['isp']}
Organización: {data['org']}
ASN: {data['asn']} ({data['asname']})
Proxy/VPN: {'Sí' if data.get('proxy') else 'No' if data.get('proxy') is not None else 'Desconocido'}
Hosting: {'Sí' if data.get('hosting') else 'No' if data.get('hosting') is not None else 'Desconocido'}
Mobile: {'Sí' if data.get('mobile') else 'No' if data.get('mobile') is not None else 'Desconocido'}"""
        
        self.summary_text.config(state="normal")
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(tk.END, basic_info)
        self.summary_text.config(state="disabled")
        
        # Detalles en treeview
        self.details_tree.delete(*self.details_tree.get_children())
        details = [
            ("IP", data['ip']),
            ("Confianza", f"{data['confidence']}%"),
            ("País", f"{data['country']} ({data['country_code']})"),
            ("Continente", f"{data['continent']} ({data['continent_code']})"),
            ("Región", data['region']),
            ("Ciudad", data['city']),
            ("Código Postal", data['zip']),
            ("Coordenadas", f"{data['latitude']}, {data['longitude']}"),
            ("Zona Horaria", data['timezone']),
            ("ISP", data['isp']),
            ("Organización", data['org']),
            ("ASN", f"{data['asn']} ({data['asname']})"),
            ("DNS Reverse", data['reverse']),
            ("Proxy/VPN", 'Sí' if data.get('proxy') else 'No' if data.get('proxy') is not None else 'Desconocido'),
            ("Hosting", 'Sí' if data.get('hosting') else 'No' if data.get('hosting') is not None else 'Desconocido'),
            ("Mobile", 'Sí' if data.get('mobile') else 'No' if data.get('mobile') is not None else 'Desconocido'),
            ("Moneda", data['currency']),
            ("Servicios Consultados", ", ".join(data['services'].keys()))
        ]
        
        for prop, value in details:
            self.details_tree.insert("", "end", values=(prop, value))
        
        # Datos técnicos (JSON completo)
        self.tech_text.config(state="normal")
        self.tech_text.delete(1.0, tk.END)
        self.tech_text.insert(tk.END, json.dumps(data, indent=2))
        self.tech_text.config(state="disabled")
        
        # Generar mapa si hay coordenadas
        if data.get('latitude') and data.get('longitude'):
            self.generate_map(data['latitude'], data['longitude'], data['city'])
        else:
            self.map_label.config(text="No hay datos de ubicación para mostrar el mapa")
        
        # Generar gráficos
        self.generate_charts(data)
        
        # Mostrar pestaña de información primero
        self.notebook.select(0)

    def generate_map(self, lat, lon, location_name):
        """Genera un mapa con la ubicación de la IP"""
        try:
            # Limpiar el contenedor del mapa
            for widget in self.map_container.winfo_children():
                widget.destroy()
            
            # Crear mapa con Folium
            m = folium.Map(
                location=[lat, lon],
                zoom_start=self.map_zoom,
                tiles=self.map_tiles
            )
            
            # Añadir marcador
            popup_text = f"<b>{location_name}</b><br>Lat: {lat:.4f}, Lon: {lon:.4f}"
            folium.Marker(
                [lat, lon],
                popup=popup_text,
                tooltip="Ver ubicación",
                icon=folium.Icon(color='red', icon='info-sign')
            ).add_to(m)
            
            # Añadir círculo de precisión (radio de 5km como ejemplo)
            folium.Circle(
                location=[lat, lon],
                radius=5000,
                color='#3186cc',
                fill=True,
                fill_color='#3186cc'
            ).add_to(m)
            
            # Guardar mapa temporalmente
            map_file = os.path.join(os.getcwd(), "temp_map.html")
            m.save(map_file)
            
            # Mostrar mapa en la interfaz usando WebView o navegador
            try:
                # Intentar usar customtkinter para mejor integración
                from webview import WebView
                webview = WebView(self.map_container, url=map_file)
                webview.pack(fill="both", expand=True)
            except:
                # Fallback: Mostrar enlace al mapa
                self.map_label = ttk.Label(
                    self.map_container,
                    text=f"Mapa generado en: {map_file}\nHaz clic en 'Abrir en Navegador' para verlo",
                    cursor="hand2"
                )
                self.map_label.pack(fill="both", expand=True)
                self.map_label.bind("<Button-1>", lambda e: webbrowser.open(map_file))
            
        except Exception as e:
            print(f"Error generando mapa: {str(e)}")
            self.map_label = ttk.Label(
                self.map_container,
                text=f"Error al generar el mapa: {str(e)}",
                foreground="red"
            )
            self.map_label.pack(fill="both", expand=True)

    def update_map(self):
        """Actualiza el mapa con la configuración actual"""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 1:  # Pestaña de mapa
            ip = self.ip_entry.get().strip()
            if ip in self.cache:
                data = self.cache[ip]["data"]
                if data.get('latitude') and data.get('longitude'):
                    self.generate_map(data['latitude'], data['longitude'], data['city'])

    def open_map_in_browser(self):
        """Abre el mapa en el navegador predeterminado"""
        map_file = os.path.join(os.getcwd(), "temp_map.html")
        if os.path.exists(map_file):
            webbrowser.open(map_file)
        else:
            messagebox.showwarning("Advertencia", "No hay mapa generado para abrir")

    def generate_charts(self, data):
        """Genera gráficos estadísticos"""
        try:
            # Limpiar frame de gráficos
            for widget in self.charts_frame.winfo_children():
                widget.destroy()
            
            # Crear figura de matplotlib
            fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(12, 4))
            fig.suptitle("Estadísticas de Geolocalización", fontsize=12)
            
            # Gráfico 1: Confianza y servicios
            services = list(data["services"].keys())
            success = [1 for _ in services]
            
            ax1.bar(services, success, color=self.colors["secondary"])
            ax1.set_title("Servicios Utilizados")
            ax1.set_ylabel("Éxito")
            ax1.tick_params(axis='x', rotation=45)
            
            # Gráfico 2: Ubicación
            ax2.scatter(data["longitude"], data["latitude"], 
                       color=self.colors["accent"], s=100)
            ax2.set_title("Ubicación Geográfica")
            ax2.set_xlabel("Longitud")
            ax2.set_ylabel("Latitud")
            
            # Gráfico 3: Tipo de conexión
            connection_types = {
                "Proxy/VPN": 1 if data.get('proxy') else 0,
                "Hosting": 1 if data.get('hosting') else 0,
                "Mobile": 1 if data.get('mobile') else 0
            }
            colors = [self.colors["success"] if v else self.colors["warning"] 
                     for v in connection_types.values()]
            
            ax3.bar(connection_types.keys(), connection_types.values(), color=colors)
            ax3.set_title("Tipo de Conexión")
            ax3.set_ylabel("Probabilidad")
            
            fig.tight_layout()
            
            # Integrar gráfico en Tkinter
            canvas = FigureCanvasTkAgg(fig, master=self.charts_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
        except Exception as e:
            print(f"Error generando gráficos: {str(e)}")
            label = ttk.Label(self.charts_frame, text=f"Error al generar gráficos: {str(e)}",
                            foreground="red")
            label.pack(fill="both", expand=True)

    def add_to_history(self, ip, data):
        """Añade una búsqueda al historial"""
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "country": data.get("country", "Desconocido"),
            "city": data.get("city", "Desconocido"),
            "isp": data.get("isp", "Desconocido"),
            "latitude": data.get("latitude", 0),
            "longitude": data.get("longitude", 0),
            "confidence": data.get("confidence", 0),
            "full_data": data
        }
        
        self.history.insert(0, entry)
        self.save_history()
        self.update_history_view()

    def load_history(self):
        """Carga el historial desde archivo"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error cargando historial: {str(e)}")
            self.history = []

    def save_history(self):
        """Guarda el historial en archivo"""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error guardando historial: {str(e)}")

    def load_cache(self):
        """Carga la caché desde archivo"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error cargando caché: {str(e)}")
            self.cache = {}

    def save_cache(self):
        """Guarda la caché en archivo"""
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error guardando caché: {str(e)}")

    def update_history_view(self):
        """Actualiza la vista del historial"""
        search_term = self.history_search_var.get().lower()
        
        self.history_tree.delete(*self.history_tree.get_children())
        
        for entry in self.history:
            if (not search_term or 
                search_term in entry["ip"].lower() or 
                search_term in entry["country"].lower() or 
                search_term in entry["city"].lower() or 
                search_term in entry["isp"].lower()):
                
                self.history_tree.insert("", "end", values=(
                    entry["timestamp"],
                    entry["ip"],
                    entry["country"],
                    entry["city"],
                    entry["isp"]
                ))

    def show_history_details(self, event):
        """Muestra los detalles de una entrada del historial"""
        selected = self.history_tree.selection()
        if not selected:
            return
            
        item = self.history_tree.item(selected[0])
        ip = item["values"][1]
        
        entry = next((e for e in self.history if e["ip"] == ip), None)
        if entry:
            self.show_details_window(entry)

    def show_details_window(self, entry):
        """Muestra una ventana con los detalles completos"""
        details_win = tk.Toplevel(self.root)
        details_win.title(f"Detalles de {entry['ip']}")
        details_win.geometry("900x700")
        
        # Frame principal
        main_frame = ttk.Frame(details_win, padding=10)
        main_frame.pack(fill="both", expand=True)
        
        # Información básica
        info_frame = ttk.LabelFrame(main_frame, text="Información Básica", padding=10)
        info_frame.pack(fill="x", pady=5)
        
        info_text = f"""IP: {entry['ip']}
Fecha/Hora: {entry['timestamp']}
País: {entry['country']}
Ciudad: {entry['city']}
ISP: {entry['isp']}
Confianza: {entry['confidence']}%
Coordenadas: {entry['latitude']}, {entry['longitude']}"""
        
        ttk.Label(info_frame, text=info_text, font=("Consolas", 11)).pack(anchor="w")
        
        # Pestañas para detalles
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)
        
        # Pestaña de datos completos
        data_frame = ttk.Frame(notebook)
        data_text = scrolledtext.ScrolledText(data_frame, wrap=tk.WORD,
                                            font=("Consolas", 10))
        data_text.insert(tk.END, json.dumps(entry["full_data"], indent=2))
        data_text.config(state="disabled")
        data_text.pack(fill="both", expand=True)
        notebook.add(data_frame, text="Datos Completos")
        
        # Pestaña de servicios
        services_frame = ttk.Frame(notebook)
        services_tree = ttk.Treeview(services_frame, columns=("service", "status"), show="headings")
        services_tree.heading("service", text="Servicio")
        services_tree.heading("status", text="Estado")
        services_tree.column("service", width=150)
        services_tree.column("status", width=600)
        
        for service, data in entry["full_data"].get("services", {}).items():
            status = "Éxito" if data else "Error"
            services_tree.insert("", "end", values=(service, status))
        
        scrollbar = ttk.Scrollbar(services_frame, orient="vertical", command=services_tree.yview)
        services_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        services_tree.pack(fill="both", expand=True)
        notebook.add(services_frame, text="Servicios")
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Copiar JSON", 
                  command=lambda: self.copy_json(entry["full_data"])).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cerrar", 
                  command=details_win.destroy).pack(side="right")

    def export_history(self):
        """Exporta el historial a un archivo JSON"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Exportar historial como JSON")
        
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.history, f, indent=2, ensure_ascii=False)
                self.status_var.set(f"Historial exportado a {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo exportar el historial: {str(e)}")

    def copy_json(self, data):
        """Copia los datos JSON al portapapeles"""
        pyperclip.copy(json.dumps(data, indent=2))
        self.status_var.set("JSON copiado al portapapeles")

    def clear_fields(self):
        """Limpia todos los campos de entrada y resultados"""
        self.ip_entry.delete(0, tk.END)
        self.summary_text.config(state="normal")
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.config(state="disabled")
        self.details_tree.delete(*self.details_tree.get_children())
        self.tech_text.config(state="normal")
        self.tech_text.delete(1.0, tk.END)
        self.tech_text.config(state="disabled")
        
        # Limpiar mapa
        for widget in self.map_container.winfo_children():
            widget.destroy()
        self.map_label = ttk.Label(self.map_container, text="El mapa se cargará con los resultados...",
                                  font=("Segoe UI", 12))
        self.map_label.pack(fill="both", expand=True)
        
        # Limpiar gráficos
        for widget in self.charts_frame.winfo_children():
            widget.destroy()
        
        self.status_var.set("Campos limpiados")

    def clear_history(self):
        """Limpia el historial de búsquedas"""
        if messagebox.askyesno("Confirmar", "¿Borrar todo el historial?"):
            self.history = []
            self.save_history()
            self.update_history_view()
            self.status_var.set("Historial borrado")

    def show_settings(self):
        """Muestra la ventana de configuración"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Configuración")
        settings_win.geometry("500x400")
        
        main_frame = ttk.Frame(settings_win, padding=15)
        main_frame.pack(fill="both", expand=True)
        
        # Configuración de mapa
        map_frame = ttk.LabelFrame(main_frame, text="Configuración del Mapa", padding=10)
        map_frame.pack(fill="x", pady=5)
        
        ttk.Label(map_frame, text="Zoom inicial:").grid(row=0, column=0, sticky="w")
        zoom_var = tk.IntVar(value=self.map_zoom)
        ttk.Spinbox(map_frame, from_=1, to=18, textvariable=zoom_var, width=5
                   ).grid(row=0, column=1, sticky="w")
        
        ttk.Label(map_frame, text="Estilo de mapa:").grid(row=1, column=0, sticky="w")
        tiles_var = tk.StringVar(value=self.map_tiles)
        ttk.Combobox(map_frame, textvariable=tiles_var, values=[
            "OpenStreetMap", "Stamen Terrain", "Stamen Toner", "CartoDB positron"
        ], state="readonly").grid(row=1, column=1, sticky="we")
        
        # Configuración de servicios
        services_frame = ttk.LabelFrame(main_frame, text="Servicios de Geolocalización", padding=10)
        services_frame.pack(fill="both", expand=True, pady=5)
        
        # Crear checkboxes para cada servicio
        self.service_vars = {}
        for i, service in enumerate(self.services.keys()):
            var = tk.BooleanVar(value=True)
            self.service_vars[service] = var
            cb = ttk.Checkbutton(services_frame, text=service, variable=var)
            cb.grid(row=i, column=0, sticky="w", padx=5, pady=2)
        
        # Botones
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Guardar", 
                  command=lambda: self.save_settings(zoom_var.get(), tiles_var.get())
                 ).pack(side="right", padx=5)
        ttk.Button(btn_frame, text="Cancelar", 
                  command=settings_win.destroy).pack(side="right", padx=5)

    def save_settings(self, zoom, tiles):
        """Guarda la configuración"""
        self.map_zoom = zoom
        self.map_tiles = tiles
        
        # Actualizar servicios activos
        for service, var in self.service_vars.items():
            self.services[service]["active"] = var.get()
        
        messagebox.showinfo("Configuración", "Los cambios se guardaron correctamente")
        self.root.focus_set()

    def show_about(self):
        """Muestra información sobre la aplicación"""
        about_text = f"""IP GeoLocator Pro BETA v1.0

Una herramienta avanzada para geolocalización de direcciones IP
que combina múltiples servicios para máxima precisión.

Características:
- Geolocalización precisa con múltiples fuentes
- Historial completo de búsquedas
- Visualización en mapa interactivo
- Estadísticas detalladas
- Soporte para IPv4 e IPv6
- Cache de resultados para mejor performance

Desarrollado con Python y Tkinter
© {datetime.now().year} - Todos los derechos reservados"""
        
        messagebox.showinfo("Acerca de IP GeoLocator Pro BETA", about_text)

    def show_help(self):
        """Muestra la ayuda de la aplicación"""
        help_text = """Cómo usar IP GeoLocator Pro BETA:

1. BÚSQUEDA:
   - Ingresa una dirección IP o dominio
   - Haz clic en "Buscar" o presiona Enter
   - Usa "Mi IP" para buscar tu dirección pública

2. RESULTADOS:
   - Información: Datos principales de geolocalización
   - Mapa: Ubicación aproximada con marcador
   - Datos Técnicos: Información cruda de los servicios
   - Gráficos: Estadísticas visuales
   - Historial: Búsquedas anteriores

3. CONFIGURACIÓN:
   - Ajusta zoom y estilo del mapa
   - Activa/desactiva servicios de geolocalización

4. EXPORTACIÓN:
   - Copia datos al portapapeles
   - Exporta historial a JSON

TIPS:
- Los resultados se cachean por 1 hora
- Usa múltiples servicios para mayor precisión
- Consulta el historial para ver búsquedas anteriores"""
        
        help_window = tk.Toplevel(self.root)
        help_window.title("Ayuda de IP GeoLocator Pro BETA")
        help_window.geometry("600x500")
        
        text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, padx=10, pady=10)
        text.insert(tk.END, help_text)
        text.config(state="disabled")
        text.pack(fill="both", expand=True)
        
        btn_frame = ttk.Frame(help_window)
        btn_frame.pack(fill="x", pady=5)
        
        ttk.Button(btn_frame, text="Cerrar", command=help_window.destroy
                  ).pack(side="right", padx=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = IPGeoLocatorBeta(root)
    root.mainloop()
