# aaf-sso

Faux serveur SAML 2.0 pour simuler le SSO de l'Académie

Pour générer un certificat clef publique clef privée:

openssl req -newkey rsa:2048 -nodes -keyout aaf-sso.key -x509 -days 3650 -out aaf-sso.csr

URL pour l'authentification des parents:
http://localhost/?idp=parents

URL pour l'authentification des agents:
http://localhost/?idp=agents
