from flask import Flask, request, jsonify
import dns.resolver
import dns.exception

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        "service": "DNS Query API",
        "usage": "/dns?domain=google.com&type=A&server=8.8.8.8",
        "params": {
            "domain": "nazwa domeny (wymagane)",
            "type": "typ rekordu: A, AAAA, MX, TXT, NS, CNAME, SOA (domyślnie: A)",
            "server": "adres serwera DNS (domyślnie: 8.8.8.8)"
        }
    })

@app.route('/dns')
def dns_query():
    domain = request.args.get('domain')
    record_type = request.args.get('type', 'A').upper()
    server = request.args.get('server', '8.8.8.8')

    if not domain:
        return jsonify({"error": "Parametr 'domain' jest wymagany"}), 400

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.timeout = 5
        resolver.lifetime = 5

        answers = resolver.resolve(domain, record_type)
        results = [str(r) for r in answers]

        return jsonify({
            "domain": domain,
            "type": record_type,
            "server": server,
            "results": results
        })

    except dns.resolver.NXDOMAIN:
        return jsonify({"error": f"Domena '{domain}' nie istnieje"}), 404
    except dns.resolver.NoAnswer:
        return jsonify({"error": f"Brak rekordów typu {record_type} dla '{domain}'"}), 404
    except dns.exception.Timeout:
        return jsonify({"error": f"Przekroczono czas odpowiedzi serwera {server}"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
