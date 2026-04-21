from flask import Flask, request, jsonify
import dns.resolver
import dns.exception
import os

app = Flask(__name__)
API_KEY = os.environ.get('API_KEY', '')

@app.before_request
def check_api_key():
    # Pomijamy sprawdzanie dla głównej strony /
    if request.path == '/':
        return
    key = request.args.get('key') or request.headers.get('X-API-Key')
    if not API_KEY or key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
import requests
import ssl
import socket
import datetime

app = Flask(__name__)

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']

def query_dns(domain, record_type, server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    resolver.timeout = 5
    resolver.lifetime = 5
    answers = resolver.resolve(domain, record_type)
    return [str(r) for r in answers]

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        expires_str = cert['notAfter']
        expires = datetime.datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
        days_left = (expires - datetime.datetime.utcnow()).days
        return {
            "valid": True,
            "expires": expires.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "subject": dict(x[0] for x in cert['subject']).get('commonName', ''),
            "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', '')
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        return {"valid": None, "error": str(e)}

@app.route('/')
def index():
    return jsonify({
        "service": "Network Monitor API",
        "endpoints": {
            "/dns": "?domain=example.com&type=A&server=8.8.8.8",
            "/http": "?url=https://example.com"
        }
    })

@app.route('/dns')
def dns_query():
    domain = request.args.get('domain')
    record_type = request.args.get('type', 'A').upper()
    server = request.args.get('server', '8.8.8.8')

    if not domain:
        return jsonify({"error": "Parametr 'domain' jest wymagany"}), 400

    if record_type == 'ANY':
        results = {}
        for rtype in RECORD_TYPES:
            try:
                results[rtype] = query_dns(domain, rtype, server)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.Timeout:
                results[rtype] = ["TIMEOUT"]
            except Exception:
                pass

        if not results:
            return jsonify({"error": f"Brak jakichkolwiek rekordów dla '{domain}'"}), 404

        return jsonify({
            "domain": domain,
            "type": "ANY",
            "server": server,
            "results": results
        })

    try:
        records = query_dns(domain, record_type, server)
        return jsonify({
            "domain": domain,
            "type": record_type,
            "server": server,
            "results": records
        })
    except dns.resolver.NXDOMAIN:
        return jsonify({"error": f"Domena '{domain}' nie istnieje"}), 404
    except dns.resolver.NoAnswer:
        return jsonify({"error": f"Brak rekordów typu {record_type} dla '{domain}'"}), 404
    except dns.exception.Timeout:
        return jsonify({"error": f"Przekroczono czas odpowiedzi serwera {server}"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/http')
def http_check():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "Parametr 'url' jest wymagany"}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = {
        "url": url,
        "checked_at": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    # redirect chain + status + czas odpowiedzi
    try:
        start = datetime.datetime.utcnow()
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 NetworkMonitor/1.0"}
        )
        elapsed_ms = int((datetime.datetime.utcnow() - start).total_seconds() * 1000)

        # redirect chain
        redirects = []
        for r in resp.history:
            redirects.append({
                "url": r.url,
                "status_code": r.status_code
            })

        result["status_code"] = resp.status_code
        result["response_time_ms"] = elapsed_ms
        result["final_url"] = resp.url
        result["redirects"] = redirects
        result["redirect_count"] = len(redirects)
        result["headers"] = {
            "server": resp.headers.get("Server", ""),
            "content_type": resp.headers.get("Content-Type", ""),
            "x_powered_by": resp.headers.get("X-Powered-By", ""),
            "strict_transport_security": resp.headers.get("Strict-Transport-Security", ""),
        }

    except requests.exceptions.Timeout:
        result["error"] = "Timeout po 10 sekundach"
        return jsonify(result), 504
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Błąd połączenia: {str(e)}"
        return jsonify(result), 502
    except Exception as e:
        result["error"] = str(e)
        return jsonify(result), 500

    # SSL (tylko dla https)
    if url.startswith('https://'):
        hostname = url.split('/')[2].split(':')[0]
        result["ssl"] = get_ssl_info(hostname)

    return jsonify(result)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
