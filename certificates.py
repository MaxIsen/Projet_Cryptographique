from OpenSSL import crypto, SSL


#function that generates certificates
def generating_certificate(
    #Mise en place des données que l'on va rentrer pour signer le certificat
    emailAddress="maxime.raillard@isen.yncrea.fr",
    commonName="Maxime",
    countryName="FR",
    localityName="localityName",
    stateOrProvinceName="Provence-Alpes-Cote-D'azur",
    organizationName="ISEN",
    organizationUnitName="ShieldFactory",
    serialNumber=0,

    #Duree de validité du certificat (10 ans ici)
    FinValiditeEnSecondes=10*365*24*60*60,

    #Fichier qui vont etre générés
    KEY_FILE = "private.key",
    CERT_FILE="IsenCertificate.crt"):

    #peut regarder dans le fichier généré en utilisant openssl
    #openssl x509 -inform pem -in IsenCertificate.crt -noout -text
    # creation d'une paire de clef de type RSA
    clef = crypto.PKey()
    clef.generate_key(crypto.TYPE_RSA, 4096)


    # Definition des elements du certificat
    certificate = crypto.X509()
    certificate.get_subject().C = countryName
    certificate.get_subject().ST = stateOrProvinceName
    certificate.get_subject().L = localityName
    certificate.get_subject().O = organizationName
    certificate.get_subject().OU = organizationUnitName
    certificate.get_subject().CN = commonName
    certificate.get_subject().emailAddress = emailAddress
    certificate.set_serial_number(serialNumber)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(FinValiditeEnSecondes)
    certificate.set_issuer(certificate.get_subject())
    certificate.set_pubkey(clef)
    certificate.sign(clef, 'sha512')

    #Creation du certificat
    with open(CERT_FILE, "wt") as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode("utf-8"))
    with open(KEY_FILE, "wt") as file:
        file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, clef).decode("utf-8"))





generating_certificate()