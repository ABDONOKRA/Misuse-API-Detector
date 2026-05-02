"""
Moteur de recommandations anti-abus.
Génère des recommandations basées sur les alertes détectées.
"""
 
 
def generate_recommendations(alerts: list) -> list[dict]:
    """
    Génère des recommandations de sécurité basées sur les alertes.
    Chaque recommandation contient : titre, description, priorité, exemple de code.
    """
    alert_types = {a.type for a in alerts}
    recommendations = []
 
    if "BRUTE_FORCE" in alert_types:
        recommendations.append({
            "title":       "Activer le rate limiting sur /login",
            "priority":    "CRITICAL",
            "description": (
                "Des tentatives de brute force ont été détectées. "
                "Limiter à 5 tentatives par IP par minute et bloquer "
                "temporairement les IPs dépassant ce seuil."
            ),
            "code": """
# Exemple Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
 
limiter = Limiter(app, key_func=get_remote_address)
 
@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
""",
        })
 
        recommendations.append({
            "title":       "Implémenter le compte-bloquage (Account Lockout)",
            "priority":    "HIGH",
            "description": (
                "Bloquer un compte après N tentatives échouées consécutives. "
                "Recommandé : 5 échecs = blocage 15 minutes."
            ),
            "code": None,
        })
 
    if "REQUEST_SPIKE" in alert_types:
        recommendations.append({
            "title":       "Déployer un CAPTCHA adaptatif",
            "priority":    "HIGH",
            "description": (
                "Des spikes de requêtes anormaux ont été détectés. "
                "Ajouter un CAPTCHA adaptatif qui se déclenche uniquement "
                "lorsque le comportement devient suspect."
            ),
            "code": None,
        })
 
        recommendations.append({
            "title":       "Configurer un WAF (Web Application Firewall)",
            "priority":    "MEDIUM",
            "description": (
                "Un WAF peut absorber les spikes de trafic et filtrer "
                "automatiquement les IP malveillantes. Options : Cloudflare, AWS WAF, nginx limit_req."
            ),
            "code": """
# Exemple configuration Nginx rate limiting
# Dans nginx.conf :
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
limit_req zone=api burst=10 nodelay;
""",
        })
 
    if "ENDPOINT_ENUMERATION" in alert_types:
        recommendations.append({
            "title":       "Masquer les messages d'erreur 404",
            "priority":    "MEDIUM",
            "description": (
                "Les erreurs 404 détaillées aident les attaquants à cartographier "
                "votre API. Retourner un message générique : 'Ressource non trouvée'."
            ),
            "code": None,
        })
 
    if "ENDPOINT_HAMMERING" in alert_types:
        recommendations.append({
            "title":       "Rate limiting par endpoint critique",
            "priority":    "HIGH",
            "description": (
                "Certains endpoints subissent un trafic excessif. "
                "Appliquer des limites spécifiques par endpoint sensible."
            ),
            "code": None,
        })
 
    # Recommandation générale toujours présente
    recommendations.append({
        "title":       "Activer la journalisation enrichie (Enhanced Logging)",
        "priority":    "LOW",
        "description": (
            "Enregistrer systématiquement : IP, user-agent, timestamp, "
            "endpoint, statut HTTP et payload size pour chaque requête mobile. "
            "Conserver les logs 90 jours minimum."
        ),
        "code": None,
    })
 
    return recommendations
