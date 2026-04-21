from flask import Flask, request, jsonify
import dns.resolver
import dns.exception

app = Flask(__name__)

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']

def query_dns(domain, record_type, server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    resolver.timeout = 5
    resolver.lifetime = 5
    answers = resolver.resolve(domain, record_type)
    return [str(r) for r in answers]

@app.route('/')
def index():
    return jsonify({
        "service": "DNS Query API",
        "usage": "/dns?domain=google.com&type=A&server=8.8.8.8",
        "params": {
            "domain": "nazwa domeny (wymagane)",
            "type": "typ rekordu: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, CAA, ANY (domyślnie: A)",
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

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
