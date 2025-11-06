## Installatie
pip install -r requirements.txt
python app.py
Open: http://127.0.0.1:5000

## Sleutelbeheer Implementatie

### 1. GENERATIE
- Methode: PBKDF2 key derivation
- Implementatie: Wachtwoord wordt omgezet naar 256-bit key
- Parameters: SHA-256, 100.000 iteraties

### 2. OPSLAG
- Methode: Encrypted file storage
- Implementatie: Key encrypted met master password
- Locatie: `keys/`

### 3. UITWISSELING
- Methode: Password-protected share package
- Implementatie: Key encrypted met recipient password
- Transport: Via email/chat bv.

## Gebruik

### Basis Workflow
1. Maak key met `create-key`
2. Encrypt data met `encrypt`
3. Deel key met `share-key`
4. Ontvanger importeert met `receive-key`
5. Ontvanger decrypt met `decrypt`

## Beveiligingsimplicaties

Voordelen:
- AES-256-GCM: Military-grade encryptie
- PBKDF2: Brute-force resistant
- Encrypted storage: Keys niet in plaintext

Nadelen:
- Password-dependent: Zwak wachtwoord = zwakke beveiliging
- Niet schaalbaar naar vele gebruikers

## Kerckhoffs's Principe

Deze implementatie voldoet aan Kerckhoffs's Principe:
- Algoritme is publiek (AES-256-GCM)
- Implementatie mag bekend zijn
- Veiligheid zit volledig in de geheime sleutel
