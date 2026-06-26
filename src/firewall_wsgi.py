"""
firewall_wsgi.py  -  WSGI/REST controller + WebSocket handler
Handles all HTTP routes and WebSocket connections.
All firewall state lives in FirewallApp (firewall_app.py).
"""

import json
import os
import ipaddress

from ryu.app.wsgi import ControllerBase, WebSocketRPCServer, websocket
from webob import Response

from firewall_app import FIREWALL_INSTANCE, WS_URL

# Absolute path to the GUI HTML file (same directory as this file)
GUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui/firewall_gui.html')


class FirewallWSGI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(FirewallWSGI, self).__init__(req, link, data, **config)
        self.app = data[FIREWALL_INSTANCE]                               # reference to FirewallApp instance

    # -- Helpers --------------------------------------------------------------

    def _json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        return Response(status=status, content_type='application/json', body=body)

    # -- Static GUI -----------------------------------------------------------

    def index(self, req, **_kw):
        with open(GUI_PATH, 'rb') as f:
            body = f.read()
        return Response(content_type='text/html', body=body)

    # -- Rules -----------------------------------------------------------------

    def get_rules(self, req, **_kw):
        app = self.app
        return self._json({
            'blocked_ips': list(app.blocked_ips),
            'blocked_ports': list(app.blocked_ports),
            'allowed_ips': list(app.allowed_ips),
            'rate_limit': app.rate_limit,
            'rate_window': app.rate_window,
        })

    def add_blocked_ip(self, req, ip, **_kw):
        try:
            ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return self._json({'status': 'error', 'msg': f'Invalid IPv4 address: {ip}'}, 400)
        
        self.app.blocked_ips.add(ip)
        self.app._flush_flows_for_ip(ip)
        self.app._log('info', f'Rule added: block IP {ip}', src=ip)
        return self._json({'status': 'ok', 'blocked_ips': list(self.app.blocked_ips)})

    def del_blocked_ip(self, req, ip, **_kw):
        try:
            ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return self._json({'status': 'error', 'msg': f'Invalid IPv4 address: {ip}'}, 400)
        if ip not in self.app.blocked_ips:
            return self._json({'status': 'error', 'msg': f'IP {ip} is not blocked'}, 404)
        
        self.app.blocked_ips.discard(ip)
        self.app._log('info', f'Rule removed: unblock IP {ip}', src=ip)
        return self._json({'status': 'ok', 'blocked_ips': list(self.app.blocked_ips)})

    def add_blocked_port(self, req, port, proto, **_kw):
        try:
            port_int = int(port)
            proto_int = int(proto)
        except ValueError:
             return self._json({'status': 'error', 'msg': 'Port and proto must be integers'}, 400)
        
        if not (0 <= port_int <= 65535):
            return self._json({'status': 'error', 'msg': f'Port {port_int} out of range (0-65535)'}, 400)
        if proto_int not in (6, 17):
            return self._json({'status': 'error', 'msg': f'Proto must be 6 (TCP) or 17 (UDP), got {proto_int}'}, 400)
        
        self.app.blocked_ports.add((port_int, proto_int))
        self.app._flush_flows_for_port(port_int, proto_int)
        self.app._log('info', f'Rule added: block protocol {proto} at port {port}')
        return self._json({'status': 'ok', 'blocked_ports': list(self.app.blocked_ports)})

    def del_blocked_port(self, req, port, proto, **_kw):
        try:
            port_int = int(port)
            proto_int = int(proto)
        except ValueError:
             return self._json({'status': 'error', 'msg': 'Port and proto must be integers'}, 400)
        
        if not (0 <= port_int <= 65535):
            return self._json({'status': 'error', 'msg': f'Port {port_int} out of range (0-65535)'}, 400)
        if proto_int not in (6, 17):
            return self._json({'status': 'error', 'msg': f'Proto must be 6 (TCP) or 17 (UDP), got {proto_int}'}, 400)

        self.app.blocked_ports.discard((port_int, proto_int))
        self.app._log('info', f'Rule removed: unblock protocol {proto} at port {port}')
        return self._json({'status': 'ok', 'blocked_ports': list(self.app.blocked_ports)})

    def set_rate_limit(self, req, **_kw):
        body = json.loads(req.body)
        self.app.rate_limit = int(body.get('limit', self.app.rate_limit))
        self.app.rate_window = int(body.get('window', self.app.rate_window))
        self.app._log('info',
            f'Rate limit updated: {self.app.rate_limit} pkts/{self.app.rate_window}s')
        return self._json({'status': 'ok'})

    # -- DPI -----------------------------------------------------------

    def get_dpi_patterns(self, req, **_kw):
        """Return all DPI patterns"""
        return self._json(self.app.dpi.list_patterns())

    def add_dpi_pattern(self, req, **_kw):
        """Add user-defined DPI pattern"""
        try:
            body = json.loads(req.body)
        except (json.JSONDecodeError, ValueError):
            return self._json({'status': 'error', 'msg': 'Invalid JSON body'}, 400)

        try:
            pattern = self.app.dpi.add_pattern(
                name=body.get('name', ''),
                raw_pattern=body.get('pattern', ''),
                description=body.get('description', ''),
            )
            self.app._flush_all_trust_flows()
            self.app._log('info', f'DPI pattern added: {pattern.name}')
            return self._json({'status': 'ok', 'pattern': pattern.name})
        except ValueError as e:
            return self._json({'status': 'error', 'msg': str(e)}, 400)

    def del_dpi_pattern(self, req, pattern_name, **_kw):
        """Delete user-defined DPI pattern, returns 403 for built-in, 404 if not found"""
        try:
            removed = self.app.dpi.remove_pattern(pattern_name)
        except ValueError as e:
            return self._json({'status': 'error', 'msg': str(e)}, 403)

        if not removed:
            return self._json({'status': 'error', 'msg': f'Pattern "{pattern_name}" not found'}, 404)

        self.app._log('info', f'DPI pattern removed: {pattern_name}')
        return self._json({'status': 'ok'})
            
    # -- Stats & log -----------------------------------------------------------

    def get_stats(self, req, **_kw):
        return self._json(self.app.stats)

    def get_log(self, req, **_kw):
        return self._json(self.app.event_log[-100:])

    # -- WebSocket -------------------------------------------------------------

    @websocket('firewall', WS_URL)
    def _ws_handler(self, ws):
        self.app.logger.debug('WebSocket connected: %s', ws)
        rpc = WebSocketRPCServer(ws, self.app)
        rpc.serve_forever()
        self.app.logger.debug('WebSocket disconnected: %s', ws)
