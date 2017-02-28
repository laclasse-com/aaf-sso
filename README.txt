
Faux serveur SAML pour simuler le SSO de l'Académie


Pour générer un certificat clef publique clef privée:

openssl req -newkey rsa:2048 -nodes -keyout aaf-sso.key -x509 -days 3650 -out aaf-sso.csr
