#!/usr/bin/env python3
"""
CyberShield Pro - نظام حماية خادم متقدم
نسخة كاملة مع جميع الميزات
"""

import os
import sys
import time
import socket
import threading
import subprocess
import platform
import json
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict

# محاولة استيراد المكتبات
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    print("⚠️  مكتبة psutil غير مثبتة. سيتم تثبيتها...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
        import psutil
        PSUTIL_AVAILABLE = True
    except:
        print("❌ تعذر تثبيت psutil، بعض الميزات محدودة")
        PSUTIL_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# ============ فئة المراقبة الكاملة ============
class AdvancedSecurityMonitor:
    def __init__(self):
        self.blocked_ips = set()
        self.connection_history = defaultdict(list)
        self.local_ips = self.get_local_ips()
        self.system_info = self.get_system_info()
        self.log_dir = "/var/log/cybershield"
        
        # إنشاء مجلدات السجلات
        os.makedirs(self.log_dir, exist_ok=True)
        
        # تحميل IPs المحظورة من ملف
        self.load_blocked_ips()
        
        print("🛡️  تم تهيئة CyberShield Pro")
        print(f"💻 النظام: {self.system_info['system']} {self.system_info['release']}")
        print(f"📍 الأجهزة الشبكية: {len(self.local_ips)}")
        print(f"📊 IPs محظورة مسبقاً: {len(self.blocked_ips)}")
    
    def load_blocked_ips(self):
        """تحميل IPs المحظورة من ملف"""
        try:
            log_file = os.path.join(self.log_dir, 'blocks.log')
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        if 'BLOCKED:' in line:
                            parts = line.split()
                            for part in parts:
                                if self.validate_ip(part):
                                    self.blocked_ips.add(part)
        except:
            pass
    
    def get_local_ips(self):
        """الحصول على جميع عناوين IP المحلية"""
        local_ips = []
        
        # الطريقة 1: استخدام socket
        try:
            hostname = socket.gethostname()
            try:
                local_ip = socket.gethostbyname(hostname)
                if local_ip and local_ip != '127.0.0.1':
                    local_ips.append({
                        'interface': 'primary',
                        'ip': local_ip,
                        'netmask': '255.255.255.0',
                        'broadcast': 'N/A'
                    })
            except socket.gaierror:
                pass
        except:
            pass
        
        # الطريقة 2: استخدام psutil إذا متاحة
        if PSUTIL_AVAILABLE:
            try:
                for name, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and addr.address and addr.address != '127.0.0.1':
                            if addr.address not in [i['ip'] for i in local_ips]:
                                local_ips.append({
                                    'interface': name,
                                    'ip': addr.address,
                                    'netmask': addr.netmask if hasattr(addr, 'netmask') else 'N/A',
                                    'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else 'N/A'
                                })
            except:
                pass
        
        return local_ips
    
    def get_system_info(self):
        """الحصول على معلومات النظام"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'hostname': socket.gethostname(),
            'fqdn': socket.getfqdn() if hasattr(socket, 'getfqdn') else socket.gethostname(),
            'processor': platform.processor() or 'N/A',
            'architecture': platform.machine(),
            'python_version': platform.python_version()
        }
        
        if PSUTIL_AVAILABLE:
            try:
                info['cpu_count'] = psutil.cpu_count()
                info['total_memory'] = psutil.virtual_memory().total
                info['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass
        
        return info
    
    def validate_ip(self, ip):
        """التحقق من صحة عنوان IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_active_connections(self):
        """الحصول على الاتصالات النشطة"""
        connections = []
        
        if not PSUTIL_AVAILABLE:
            return connections
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.laddr:
                        connection_info = {
                            'local_ip': conn.laddr.ip if hasattr(conn.laddr, 'ip') else str(conn.laddr),
                            'local_port': conn.laddr.port if hasattr(conn.laddr, 'port') else 0,
                            'remote_ip': conn.raddr.ip if conn.raddr and hasattr(conn.raddr, 'ip') else None,
                            'remote_port': conn.raddr.port if conn.raddr and hasattr(conn.raddr, 'port') else None,
                            'protocol': str(conn.type),
                            'pid': conn.pid,
                            'status': str(conn.status)
                        }
                        
                        # معلومات العملية
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                connection_info['process_name'] = proc.name()
                                try:
                                    connection_info['process_cmdline'] = ' '.join(proc.cmdline())[:50] if proc.cmdline() else 'N/A'
                                except:
                                    connection_info['process_cmdline'] = 'N/A'
                                connection_info['process_user'] = proc.username()
                            except:
                                connection_info['process_name'] = 'Unknown'
                                connection_info['process_cmdline'] = 'N/A'
                                connection_info['process_user'] = 'N/A'
                        else:
                            connection_info['process_name'] = 'N/A'
                        
                        # تحديد نوع الاتصال
                        if not connection_info['remote_ip'] or connection_info['remote_ip'] in ['0.0.0.0', '::']:
                            connection_info['connection_type'] = 'LISTENING'
                        else:
                            connection_info['connection_type'] = 'ESTABLISHED'
                        
                        connections.append(connection_info)
                except:
                    continue
        except Exception as e:
            print(f"⚠️  خطأ في قراءة الاتصالات: {e}")
        
        return connections
    
    def get_listening_ports(self):
        """الحصول على المنافذ المستمع عليها"""
        listening = []
        
        if not PSUTIL_AVAILABLE:
            return listening
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    info = {
                        'ip': conn.laddr.ip if hasattr(conn.laddr, 'ip') else str(conn.laddr),
                        'port': conn.laddr.port if hasattr(conn.laddr, 'port') else 0,
                        'protocol': str(conn.type),
                        'pid': conn.pid
                    }
                    
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            info['process'] = proc.name()
                            info['user'] = proc.username()
                        except:
                            info['process'] = 'Unknown'
                            info['user'] = 'N/A'
                    
                    listening.append(info)
        except:
            pass
        
        return listening
    
    def block_ip(self, ip, reason=""):
        """حظر IP"""
        if not self.validate_ip(ip):
            print(f"❌ عنوان IP غير صحيح: {ip}")
            return False
        
        # التحقق إذا كان IP محلي
        local_ips = [info['ip'] for info in self.local_ips]
        if ip in local_ips or ip == '127.0.0.1':
            print(f"⚠️  لا يمكن حظر عنوان IP محلي: {ip}")
            return False
        
        try:
            # حظر باستخدام iptables
            result1 = subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                                    capture_output=True, text=True, timeout=3)
            
            result2 = subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'LOG', 
                                    '--log-prefix', f'[CyberShield-BLOCKED {ip}] ', '--log-level', '4'], 
                                    capture_output=True, text=True, timeout=3)
            
            if result1.returncode == 0:
                self.blocked_ips.add(ip)
                print(f"✅ تم حظر {ip} بنجاح")
                
                # تسجيل في ملف
                log_file = os.path.join(self.log_dir, 'blocks.log')
                with open(log_file, 'a') as f:
                    f.write(f"{datetime.now()} - BLOCKED: {ip} - Reason: {reason}\n")
                
                return True
            else:
                print(f"❌ فشل حظر {ip}: {result1.stderr}")
                return False
            
        except Exception as e:
            print(f"❌ خطأ في حظر {ip}: {e}")
            return False
    
    def unblock_ip(self, ip):
        """إلغاء حظر IP"""
        try:
            # إزالة قاعدة iptables
            result = subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], 
                                   capture_output=True, text=True, timeout=3)
            
            if result.returncode == 0 or "Bad rule" in result.stderr:
                self.blocked_ips.discard(ip)
                print(f"✅ تم إلغاء حظر {ip}")
                
                # تسجيل في ملف
                log_file = os.path.join(self.log_dir, 'unblocks.log')
                with open(log_file, 'a') as f:
                    f.write(f"{datetime.now()} - UNBLOCKED: {ip}\n")
                
                return True
            else:
                print(f"❌ فشل إلغاء حظر {ip}: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ خطأ في إلغاء حظر {ip}: {e}")
            return False
    
    def analyze_threats(self):
        """كشف التهديدات"""
        threats = []
        connections = self.get_active_connections()
        
        # تحليل الأنماط
        ip_patterns = defaultdict(lambda: {'count': 0, 'ports': set(), 'processes': set()})
        
        for conn in connections:
            remote_ip = conn.get('remote_ip')
            if remote_ip and remote_ip not in ['0.0.0.0', '::', '127.0.0.1', None]:
                ip_patterns[remote_ip]['count'] += 1
                if conn.get('remote_port'):
                    ip_patterns[remote_ip]['ports'].add(conn['remote_port'])
                if conn.get('process_name'):
                    ip_patterns[remote_ip]['processes'].add(conn['process_name'])
        
        # كشف الهجمات
        current_time = time.time()
        for ip, pattern in ip_patterns.items():
            # تسجيل في التاريخ
            self.connection_history[ip].append(current_time)
            
            # تنظيف القديم (آخر 60 ثانية)
            self.connection_history[ip] = [
                t for t in self.connection_history[ip] 
                if current_time - t < 60
            ]
            
            connection_count = len(self.connection_history[ip])
            port_count = len(pattern['ports'])
            
            # كشف DDoS
            if connection_count > 50:
                threat = {
                    'ip': ip,
                    'type': 'DDoS Attack',
                    'severity': 'HIGH',
                    'count': connection_count,
                    'ports': port_count,
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'description': f'هجوم DDoS - {connection_count} اتصال في الدقيقة'
                }
                threats.append(threat)
                
                # حظر تلقائي
                if ip not in self.blocked_ips:
                    self.block_ip(ip, "DDoS Attack")
            
            # كشف مسح المنافذ
            elif port_count > 10 and connection_count > 20:
                threat = {
                    'ip': ip,
                    'type': 'Port Scanning',
                    'severity': 'MEDIUM',
                    'count': connection_count,
                    'ports': port_count,
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'description': f'مسح منافذ - {port_count} منفذ مختلف'
                }
                threats.append(threat)
            
            # اتصالات غير عادية
            elif connection_count > 30:
                threat = {
                    'ip': ip,
                    'type': 'Suspicious Activity',
                    'severity': 'LOW',
                    'count': connection_count,
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'description': f'نشاط مشبوه - {connection_count} اتصال'
                }
                threats.append(threat)
        
        return threats
    
    def get_system_stats(self):
        """الحصول على إحصائيات النظام"""
        stats = {}
        
        if PSUTIL_AVAILABLE:
            try:
                # CPU
                stats['cpu_percent'] = psutil.cpu_percent(interval=0.5)
                stats['cpu_count'] = psutil.cpu_count()
                try:
                    cpu_freq = psutil.cpu_freq()
                    stats['cpu_freq'] = cpu_freq.current if cpu_freq else 'N/A'
                except:
                    stats['cpu_freq'] = 'N/A'
                
                # الذاكرة
                mem = psutil.virtual_memory()
                stats['mem_total'] = mem.total
                stats['mem_used'] = mem.used
                stats['mem_percent'] = mem.percent
                stats['mem_available'] = mem.available
                
                # القرص
                disk = psutil.disk_usage('/')
                stats['disk_total'] = disk.total
                stats['disk_used'] = disk.used
                stats['disk_percent'] = disk.percent
                
                # الشبكة
                net = psutil.net_io_counters()
                stats['bytes_sent'] = net.bytes_sent
                stats['bytes_recv'] = net.bytes_recv
                stats['packets_sent'] = net.packets_sent
                stats['packets_recv'] = net.packets_recv
                
                # العمليات
                stats['process_count'] = len(list(psutil.process_iter()))
                
                # الاتصالات
                connections = self.get_active_connections()
                stats['connections'] = len(connections)
                remote_ips = set()
                for conn in connections:
                    if conn.get('remote_ip'):
                        remote_ips.add(conn['remote_ip'])
                stats['unique_ips'] = len(remote_ips)
                
            except Exception as e:
                print(f"⚠️  خطأ في قراءة إحصائيات النظام: {e}")
        
        return stats

# ============ الواجهة الكاملة ============
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def show_banner():
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                 🛡️  CYBERSHIELD PRO                     ║
    ║           نظام حماية خادم متقدم ومتكامل                 ║
    ╚══════════════════════════════════════════════════════════╝
    """)

def show_menu():
    print("""
    📋 القائمة الرئيسية:
    ──────────────────────────────────────────────
    [1]  عرض معلومات النظام والشبكة
    [2]  عرض الاتصالات النشطة (مفصّل)
    [3]  عرض المنافذ المستمع عليها
    [4]  كشف التهديدات والأخطار
    [5]  إدارة الحظر (حظر/إلغاء حظر IP)
    [6]  عرض IPs المحظورة
    [7]  مراقبة النظام في الوقت الحقيقي
    [8]  إحصائيات وأداء النظام
    [9]  بدء/إيقاف المراقبة التلقائية
    [10] تصدير تقرير
    [0]  خروج
    """)

def format_bytes(size):
    """تنسيق حجم البيانات"""
    if not size:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def show_system_info(monitor):
    """عرض معلومات النظام"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("💻 معلومات النظام الأساسية:")
    print("="*80)
    
    info = monitor.system_info
    print(f"🔸 اسم الجهاز: {info['hostname']}")
    print(f"🔸 اسم النطاق الكامل: {info['fqdn']}")
    print(f"🔸 نظام التشغيل: {info['system']} {info['release']}")
    print(f"🔸 إصدار Python: {info['python_version']}")
    print(f"🔸 المعالج: {info['processor']}")
    print(f"🔸 البنية: {info['architecture']}")
    
    if 'cpu_count' in info:
        print(f"🔸 عدد النوى: {info['cpu_count']}")
    if 'total_memory' in info:
        print(f"🔸 الذاكرة الإجمالية: {format_bytes(info['total_memory'])}")
    if 'boot_time' in info:
        print(f"🔸 وقت التمهيد: {info['boot_time']}")
    
    print("\n" + "="*80)
    print("🌐 معلومات الشبكة المحلية:")
    print("="*80)
    
    if monitor.local_ips:
        for idx, net_info in enumerate(monitor.local_ips, 1):
            print(f"\n🔹 الواجهة {idx}: {net_info['interface']}")
            print(f"   IP: {net_info['ip']}")
            print(f"   الشبكة الفرعية: {net_info['netmask']}")
            if net_info['broadcast'] != 'N/A':
                print(f"   البث: {net_info['broadcast']}")
    else:
        print("⚠️  لا توجد واجهات شبكية نشطة")

def show_detailed_connections(monitor):
    """عرض الاتصالات النشطة"""
    clear_screen()
    show_banner()
    
    connections = monitor.get_active_connections()
    
    print("\n" + "="*100)
    print(f"🔗 الاتصالات النشطة ({len(connections)} اتصال):")
    print("="*100)
    
    if connections:
        print(f"{'المحلي (جهازك)':<30} {'الطرف الآخر':<30} {'النوع':<12} {'العملية':<20}")
        print("-" * 100)
        
        for conn in connections[:40]:
            local = f"{conn['local_ip']}:{conn['local_port']}"
            remote = f"{conn['remote_ip']}:{conn['remote_port']}" if conn['remote_ip'] else "LISTENING"
            
            # تحديد الرمز المناسب
            if conn['connection_type'] == 'LISTENING':
                icon = "👂"
            elif conn['status'] == 'ESTABLISHED':
                icon = "🔗"
            else:
                icon = "❓"
            
            process = conn['process_name'][:18] if conn['process_name'] != 'N/A' else 'System'
            
            print(f"{icon} {local:<30} {remote:<30} {conn['connection_type']:<12} {process:<20}")
        
        if len(connections) > 40:
            print(f"\n... وعرض {len(connections) - 40} اتصال إضافي")
        
        # إحصائيات سريعة
        listening = sum(1 for c in connections if c['connection_type'] == 'LISTENING')
        established = sum(1 for c in connections if c['connection_type'] == 'ESTABLISHED')
        print(f"\n📊 إحصائيات سريعة:")
        print(f"   👂 مستمع: {listening}")
        print(f"   🔗 نشط: {established}")
    else:
        print("⚠️  لا توجد اتصالات نشطة حالياً")

def show_listening_ports(monitor):
    """عرض المنافذ المستمع عليها"""
    clear_screen()
    show_banner()
    
    listening = monitor.get_listening_ports()
    
    print("\n" + "="*80)
    print(f"👂 المنافذ المستمع عليها ({len(listening)} منفذ):")
    print("="*80)
    
    if listening:
        # تصنيف حسب المنفذ
        well_known = []
        registered = []
        dynamic = []
        
        for port_info in listening:
            port = port_info['port']
            if port < 1024:
                well_known.append(port_info)
            elif port < 49152:
                registered.append(port_info)
            else:
                dynamic.append(port_info)
        
        print(f"\n📁 المنافذ المعروفة (<1024): {len(well_known)}")
        if well_known:
            print(f"{'IP':<20} {'Port':<10} {'العملية':<20} {'المستخدم':<15}")
            print("-" * 65)
            for port_info in well_known[:15]:
                process = port_info.get('process', 'Unknown')[:18]
                user = port_info.get('user', 'N/A')[:12]
                print(f"{port_info['ip']:<20} {port_info['port']:<10} {process:<20} {user:<15}")
        
        print(f"\n📁 المنافذ المسجلة (1024-49151): {len(registered)}")
        if registered:
            print(f"{'IP':<20} {'Port':<10} {'العملية':<20} {'المستخدم':<15}")
            print("-" * 65)
            for port_info in registered[:10]:
                process = port_info.get('process', 'Unknown')[:18]
                user = port_info.get('user', 'N/A')[:12]
                print(f"{port_info['ip']:<20} {port_info['port']:<10} {process:<20} {user:<15}")
        
        print(f"\n📁 المنافذ الديناميكية (>49151): {len(dynamic)}")
        if dynamic:
            print(f"{'IP':<20} {'Port':<10} {'العملية':<20}")
            print("-" * 50)
            for port_info in dynamic[:5]:
                process = port_info.get('process', 'Unknown')[:18]
                print(f"{port_info['ip']:<20} {port_info['port']:<10} {process:<20}")
    else:
        print("⚠️  لا توجد منافذ مستمع عليها")

def show_threats(monitor):
    """عرض التهديدات"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("🔍 فحص التهديدات والأخطار...")
    print("="*80)
    
    threats = monitor.analyze_threats()
    
    if threats:
        high = [t for t in threats if t['severity'] == 'HIGH']
        medium = [t for t in threats if t['severity'] == 'MEDIUM']
        low = [t for t in threats if t['severity'] == 'LOW']
        
        print(f"\n⚠️  تم اكتشاف {len(threats)} تهديد:")
        print(f"   🔴 خطورة عالية: {len(high)}")
        print(f"   🟡 خطورة متوسطة: {len(medium)}")
        print(f"   🟢 خطورة منخفضة: {len(low)}")
        
        print("\n" + "="*80)
        print("📋 تفاصيل التهديدات:")
        print("="*80)
        
        for threat in threats[:10]:
            if threat['severity'] == 'HIGH':
                icon = "🔴"
            elif threat['severity'] == 'MEDIUM':
                icon = "🟡"
            else:
                icon = "🟢"
            
            print(f"\n{icon} [{threat['severity']}] {threat['type']}")
            print(f"   📍 IP: {threat['ip']}")
            print(f"   📊 عدد الاتصالات: {threat['count']}")
            print(f"   🕒 الوقت: {threat['time']}")
            print(f"   📝 الوصف: {threat['description']}")
            
            # اقتراحات
            if threat['severity'] == 'HIGH':
                print(f"   💡 الإجراء: تم الحظر تلقائياً")
            elif threat['severity'] == 'MEDIUM':
                print(f"   💡 الإجراء: مراقبة عن كثب")
        
        if len(threats) > 10:
            print(f"\n... و {len(threats) - 10} تهديد إضافي")
    else:
        print("\n✅ لم يتم اكتشاف أي تهديدات أمنية")
        print("   حالة النظام: آمن 🟢")

def manage_blocking(monitor):
    """إدارة الحظر"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("🔨 إدارة حظر IP:")
    print("="*80)
    
    print("\n[1] حظر IP يدوياً")
    print("[2] إلغاء حظر IP")
    print("[3] العودة")
    
    choice = input("\nاختر خياراً: ").strip()
    
    if choice == '1':
        print("\n" + "-"*50)
        ip = input("أدخل عنوان IP للحظر: ").strip()
        
        if not monitor.validate_ip(ip):
            print("❌ عنوان IP غير صحيح")
            return
        
        local_ips = [info['ip'] for info in monitor.local_ips]
        if ip in local_ips or ip == '127.0.0.1':
            print(f"⚠️  لا يمكن حظر عنوان IP محلي: {ip}")
            return
        
        reason = input("سبب الحظر (اختياري): ").strip()
        
        confirm = input(f"هل أنت متأكد من حظر {ip}؟ (y/n): ").strip().lower()
        if confirm == 'y':
            monitor.block_ip(ip, reason)
        else:
            print("❌ تم إلغاء العملية")
    
    elif choice == '2':
        print("\n" + "-"*50)
        
        if monitor.blocked_ips:
            print("📋 IPs المحظورة حالياً:")
            for idx, ip in enumerate(monitor.blocked_ips, 1):
                print(f"  {idx}. {ip}")
            
            ip = input("\nأدخل عنوان IP لإلغاء الحظر: ").strip()
            monitor.unblock_ip(ip)
        else:
            print("✅ لا توجد IPs محظورة حالياً")
    
    time.sleep(2)

def show_blocked_ips(monitor):
    """عرض IPs المحظورة"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("🚫 عناوين IP المحظورة:")
    print("="*80)
    
    if monitor.blocked_ips:
        print(f"\n📊 العدد الإجمالي: {len(monitor.blocked_ips)}")
        print("-" * 50)
        
        for idx, ip in enumerate(sorted(monitor.blocked_ips), 1):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{idx:3}. {ip:<20} 🔗 {hostname}")
            except:
                print(f"{idx:3}. {ip:<20} ⚠️  مجهول")
        
        print("\n💡 اقتراحات:")
        print("   • لحذف IP من القائمة، استخدم خيار 'إدارة الحظر'")
        print("   • يمكن مراجعة سجل الحظر في /var/log/cybershield/blocks.log")
    else:
        print("\n✅ لا توجد عناوين IP محظورة حالياً")
        print("   حالة الحماية: نشطة وجاهزة")

def real_time_monitor(monitor):
    """مراقبة النظام في الوقت الحقيقي"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("📊 مراقبة النظام في الوقت الحقيقي")
    print("="*80)
    print("⏱️  سيتم تحديث المعلومات كل 3 ثوانٍ")
    print("⏸️  اضغط Ctrl+C لإيقاف المراقبة والعودة")
    print("-" * 80)
    
    try:
        while True:
            if not PSUTIL_AVAILABLE:
                print("\n❌ مكتبة psutil غير متاحة للمراقبة الحية")
                break
            
            stats = monitor.get_system_stats()
            
            # تحديث الشاشة
            print("\033[2J\033[H")  # مسح الشاشة
            show_banner()
            print("\n" + "="*80)
            print(f"📊 مراقبة حية - {datetime.now().strftime('%H:%M:%S')}")
            print("="*80)
            
            if stats:
                # CPU
                cpu_percent = stats.get('cpu_percent', 0)
                cpu_bar = "█" * int(cpu_percent / 5) + "░" * (20 - int(cpu_percent / 5))
                print(f"\n🎯 CPU: {cpu_percent:.1f}% [{cpu_bar}]")
                
                # الذاكرة
                mem_percent = stats.get('mem_percent', 0)
                mem_bar = "█" * int(mem_percent / 5) + "░" * (20 - int(mem_percent / 5))
                print(f"💾 الذاكرة: {mem_percent:.1f}% [{mem_bar}]")
                if 'mem_used' in stats and 'mem_available' in stats:
                    print(f"   المستخدم: {format_bytes(stats['mem_used'])}")
                    print(f"   المتاح: {format_bytes(stats['mem_available'])}")
                
                # القرص
                disk_percent = stats.get('disk_percent', 0)
                disk_bar = "█" * int(disk_percent / 5) + "░" * (20 - int(disk_percent / 5))
                print(f"💿 القرص: {disk_percent:.1f}% [{disk_bar}]")
                
                # الشبكة
                print(f"\n🌐 الشبكة:")
                if 'bytes_sent' in stats and 'bytes_recv' in stats:
                    print(f"   ⬆️  مرسل: {format_bytes(stats['bytes_sent'])}")
                    print(f"   ⬇️  مستقبل: {format_bytes(stats['bytes_recv'])}")
                
                # الاتصالات
                print(f"\n🔗 الاتصالات:")
                print(f"   نشطة: {stats.get('connections', 0)}")
                print(f"   أجهزة فريدة: {stats.get('unique_ips', 0)}")
                print(f"   عمليات: {stats.get('process_count', 0)}")
                
                # IPs محظورة
                print(f"   IPs محظورة: {len(monitor.blocked_ips)}")
            
            print("\n" + "-" * 80)
            print("⏱️  التحديث التالي خلال 3 ثوانٍ...")
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        print("\n\n⏹️  تم إيقاف المراقبة الحية")
        time.sleep(1)

def show_system_stats(monitor):
    """عرض إحصائيات النظام"""
    clear_screen()
    show_banner()
    
    if not PSUTIL_AVAILABLE:
        print("\n❌ مكتبة psutil غير متاحة لعرض الإحصائيات")
        input("\n↵ اضغط Enter للمتابعة...")
        return
    
    stats = monitor.get_system_stats()
    
    print("\n" + "="*80)
    print("📈 إحصائيات وأداء النظام:")
    print("="*80)
    
    if stats:
        print(f"\n💻 الموارد:")
        print(f"   • المعالجات: {stats.get('cpu_count', 'N/A')} نواة")
        print(f"   • تردد CPU: {stats.get('cpu_freq', 'N/A')} MHz")
        print(f"   • استخدام CPU الحالي: {stats.get('cpu_percent', 0):.1f}%")
        
        print(f"\n💾 الذاكرة:")
        print(f"   • الإجمالي: {format_bytes(stats.get('mem_total', 0))}")
        print(f"   • المستخدم: {format_bytes(stats.get('mem_used', 0))} ({stats.get('mem_percent', 0):.1f}%)")
        print(f"   • المتاح: {format_bytes(stats.get('mem_available', 0))}")
        
        print(f"\n💿 التخزين (/):")
        print(f"   • الإجمالي: {format_bytes(stats.get('disk_total', 0))}")
        print(f"   • المستخدم: {format_bytes(stats.get('disk_used', 0))} ({stats.get('disk_percent', 0):.1f}%)")
        print(f"   • الحر: {format_bytes(stats.get('disk_total', 0) - stats.get('disk_used', 0))}")
        
        print(f"\n🌐 الشبكة:")
        if 'bytes_sent' in stats:
            print(f"   • بيانات مرسلة: {format_bytes(stats['bytes_sent'])}")
            print(f"   • بيانات مستلمة: {format_bytes(stats['bytes_recv'])}")
        
        print(f"\n🔗 اتصالات الشبكة:")
        print(f"   • اتصالات نشطة: {stats.get('connections', 0)}")
        print(f"   • عناوين IP فريدة: {stats.get('unique_ips', 0)}")
        print(f"   • IPs محظورة: {len(monitor.blocked_ips)}")
        
        print(f"\n⚙️  النظام:")
        print(f"   • عدد العمليات: {stats.get('process_count', 0)}")
        print(f"   • الوقت الحالي: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if PSUTIL_AVAILABLE:
            print(f"   • مدة تشغيل النظام: {time.time() - psutil.boot_time():.0f} ثانية")

def auto_monitoring_control(monitor):
    """التحكم في المراقبة التلقائية"""
    global auto_monitor_thread
    global auto_monitor_running
    
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("🤖 المراقبة التلقائية:")
    print("="*80)
    
    if 'auto_monitor_running' not in globals():
        globals()['auto_monitor_running'] = False
    
    if auto_monitor_running:
        print("\n✅ المراقبة التلقائية تعمل حالياً")
        print("\n[1] إيقاف المراقبة التلقائية")
        print("[2] العودة")
        
        choice = input("\nاختر خياراً: ").strip()
        
        if choice == '1':
            auto_monitor_running = False
            if 'auto_monitor_thread' in globals():
                auto_monitor_thread.join(timeout=2)
            print("⏹️  تم إيقاف المراقبة التلقائية")
            time.sleep(1)
    
    else:
        print("\n⏸️  المراقبة التلقائية متوقفة حالياً")
        print("\n[1] بدء المراقبة التلقائية")
        print("[2] العودة")
        
        choice = input("\nاختر خياراً: ").strip()
        
        if choice == '1':
            auto_monitor_running = True
            
            def auto_monitor():
                log_file = os.path.join(monitor.log_dir, 'auto_monitor.log')
                
                while auto_monitor_running:
                    try:
                        # فحص التهديدات
                        threats = monitor.analyze_threats()
                        
                        if threats:
                            # تسجيل التهديدات
                            with open(log_file, 'a') as f:
                                for threat in threats:
                                    f.write(f"{datetime.now()} - {threat['severity']} - {threat['type']} - {threat['ip']}\n")
                        
                        # تسجيل حالة النظام كل دقيقة
                        if int(time.time()) % 60 < 3:
                            stats = monitor.get_system_stats()
                            with open(log_file, 'a') as f:
                                f.write(f"{datetime.now()} - SYSTEM - CPU: {stats.get('cpu_percent', 0)}% - MEM: {stats.get('mem_percent', 0)}% - CONN: {stats.get('connections', 0)}\n")
                        
                        time.sleep(10)
                        
                    except Exception as e:
                        with open(log_file, 'a') as f:
                            f.write(f"{datetime.now()} - ERROR - {str(e)}\n")
                        time.sleep(10)
            
            globals()['auto_monitor_thread'] = threading.Thread(target=auto_monitor, daemon=True)
            auto_monitor_thread.start()
            
            print("🚀 تم بدء المراقبة التلقائية")
            print(f"📝 يتم التسجيل في {os.path.join(monitor.log_dir, 'auto_monitor.log')}")
            time.sleep(2)

def export_report(monitor):
    """تصدير تقرير"""
    clear_screen()
    show_banner()
    
    print("\n" + "="*80)
    print("📄 تصدير تقرير:")
    print("="*80)
    
    filename = input("\nأدخل اسم الملف للتقرير (بدون امتداد): ").strip()
    if not filename:
        filename = f"cybershield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    filename = f"{filename}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("تقرير CyberShield Pro\n")
            f.write(f"وقت التصدير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            # معلومات النظام
            f.write("معلومات النظام:\n")
            f.write("-" * 40 + "\n")
            for key, value in monitor.system_info.items():
                f.write(f"{key}: {value}\n")
            
            # معلومات الشبكة المحلية
            f.write("\nمعلومات الشبكة المحلية:\n")
            f.write("-" * 40 + "\n")
            for net_info in monitor.local_ips:
                f.write(f"واجهة: {net_info['interface']}\n")
                f.write(f"  IP: {net_info['ip']}\n")
                f.write(f"  قناع الشبكة: {net_info['netmask']}\n")
                if net_info['broadcast'] != 'N/A':
                    f.write(f"  عنوان البث: {net_info['broadcast']}\n")
                f.write("\n")
            
            # الاتصالات النشطة
            connections = monitor.get_active_connections()
            f.write(f"الاتصالات النشطة ({len(connections)}):\n")
            f.write("-" * 40 + "\n")
            for conn in connections[:50]:
                local = f"{conn['local_ip']}:{conn['local_port']}"
                remote = f"{conn['remote_ip']}:{conn['remote_port']}" if conn['remote_ip'] else "LISTENING"
                f.write(f"{local} <-> {remote} | {conn.get('protocol', 'N/A')} | {conn.get('process_name', 'N/A')}\n")
            
            # IPs محظورة
            f.write(f"\nعناوين IP المحظورة ({len(monitor.blocked_ips)}):\n")
            f.write("-" * 40 + "\n")
            for ip in sorted(monitor.blocked_ips):
                f.write(f"{ip}\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("نهاية التقرير\n")
            f.write("=" * 60 + "\n")
        
        print(f"✅ تم تصدير التقرير إلى: {filename}")
        print(f"📄 حجم الملف: {os.path.getsize(filename)} بايت")
        
    except Exception as e:
        print(f"❌ خطأ في تصدير التقرير: {e}")
    
    time.sleep(2)

def main():
    """الدالة الرئيسية"""
    # التحقق من صلاحيات root
    if os.geteuid() != 0:
        print("يجب تشغيل النظام كـ root")
        print("استخدم: sudo python3 cyber_shield_pro.py")
        sys.exit(1)
    
    # إنشاء المراقب
    try:
        monitor = AdvancedSecurityMonitor()
    except Exception as e:
        print(f"❌ خطأ في تهيئة النظام: {e}")
        sys.exit(1)
    
    # متغيرات المراقبة التلقائية
    auto_monitor_running = False
    auto_monitor_thread = None
    
    while True:
        clear_screen()
        show_banner()
        show_menu()
        
        try:
            choice = input("\n📝 اختر خياراً: ").strip()
            
            if choice == '1':
                show_system_info(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '2':
                show_detailed_connections(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '3':
                show_listening_ports(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '4':
                show_threats(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '5':
                manage_blocking(monitor)
            
            elif choice == '6':
                show_blocked_ips(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '7':
                real_time_monitor(monitor)
            
            elif choice == '8':
                show_system_stats(monitor)
                input("\n↵ اضغط Enter للمتابعة...")
            
            elif choice == '9':
                auto_monitoring_control(monitor)
            
            elif choice == '10':
                export_report(monitor)
            
            elif choice == '0':
                print("\n👋 إغلاق CyberShield Pro...")
                
                # إيقاف المراقبة التلقائية إذا كانت تعمل
                if auto_monitor_running:
                    auto_monitor_running = False
                    print("⏹️  إيقاف المراقبة التلقائية...")
                    if auto_monitor_thread:
                        auto_monitor_thread.join(timeout=2)
                
                print("✅ تم الخروج بنجاح")
                break
            
            else:
                print("❌ خيار غير صحيح")
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n👋 إغلاق النظام...")
            break
        except Exception as e:
            print(f"❌ خطأ غير متوقع: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()