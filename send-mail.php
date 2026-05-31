<?php
/**
 * send-mail.php — Nurset YAZGOREN Expert Bâtiment
 * Formulaire de contact sécurisé avec Cloudflare Turnstile
 *
 * CONFIGURATION : remplacez les valeurs dans la section CONFIG ci-dessous
 * avant la mise en production.
 */

// ─────────────────────────────────────────────
//  CONFIGURATION — à adapter
// ─────────────────────────────────────────────
define('CF_TURNSTILE_SECRET',  'VOTRE_CLE_SECRETE_TURNSTILE_ICI');  // Cloudflare → Turnstile → Secret key
define('MAIL_DESTINATAIRE',    'contact@yazgoren-expert.fr');         // Email qui reçoit les demandes
define('MAIL_EXPEDITEUR_FROM', 'noreply@yazgoren-expert.fr');         // Expéditeur technique (domaine identique recommandé)
define('MAIL_SUJET_PREFIX',    '[Expertise Bâtiment]');               // Préfixe dans l'objet du mail
define('ORIGINE_AUTORISEE',    'https://www.yazgoren-expert.fr');     // URL de votre site (sans slash final)
// ─────────────────────────────────────────────


// ── 1. En-têtes de sécurité HTTP ─────────────
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

// ── 2. Méthode POST uniquement ────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['success' => false, 'message' => 'Méthode non autorisée.']));
}

// ── 3. Vérification de l'origine (CSRF basique) ──
$origin  = $_SERVER['HTTP_ORIGIN']  ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';

$origineOk = (
    str_starts_with($origin,  ORIGINE_AUTORISEE) ||
    str_starts_with($referer, ORIGINE_AUTORISEE)
);

if (!$origineOk) {
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Origine non autorisée.']));
}

// ── 4. Limite de taille de la requête ────────
if ((int)$_SERVER['CONTENT_LENGTH'] > 20480) { // 20 Ko max
    http_response_code(413);
    exit(json_encode(['success' => false, 'message' => 'Requête trop volumineuse.']));
}

// ── 5. Récupération et nettoyage des champs ──
function propre(string $valeur, int $maxLen = 255): string {
    return htmlspecialchars(
        trim(strip_tags(substr($valeur, 0, $maxLen))),
        ENT_QUOTES | ENT_HTML5,
        'UTF-8'
    );
}

$prenom       = propre($_POST['prenom']      ?? '');
$nom          = propre($_POST['nom']         ?? '');
$telephone    = propre($_POST['telephone']   ?? '', 30);
$email        = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
$typeExpert   = propre($_POST['type_expertise'] ?? '');
$adresseBien  = propre($_POST['adresse_bien']   ?? '');
$superficie   = propre($_POST['superficie']     ?? '', 50);
$description  = propre($_POST['description']    ?? '', 2000);
$cfToken      = trim($_POST['cf-turnstile-response'] ?? '');

// ── 6. Validation des champs obligatoires ────
$erreurs = [];

if (empty($prenom))    $erreurs[] = 'Le prénom est requis.';
if (empty($nom))       $erreurs[] = 'Le nom est requis.';
if (empty($telephone) && empty($email)) {
    $erreurs[] = 'Veuillez fournir au moins un téléphone ou un email.';
}
if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $erreurs[] = 'L\'adresse email est invalide.';
}
if (empty($typeExpert))  $erreurs[] = 'Le type d\'expertise est requis.';
if (empty($description)) $erreurs[] = 'La description est requise.';
if (empty($cfToken))     $erreurs[] = 'Vérification anti-robot manquante.';

if (!empty($erreurs)) {
    http_response_code(422);
    exit(json_encode(['success' => false, 'message' => implode(' ', $erreurs)]));
}

// ── 7. Vérification Cloudflare Turnstile ─────
function verifierTurnstile(string $token, string $secret, string $ip): bool {
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $secret,
            'response' => $token,
            'remoteip' => $ip,
        ]),
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $reponse = curl_exec($ch);
    $errCurl = curl_errno($ch);
    curl_close($ch);

    if ($errCurl || !$reponse) return false;

    $data = json_decode($reponse, true);
    return isset($data['success']) && $data['success'] === true;
}

$ip = $_SERVER['HTTP_CF_CONNECTING_IP']  // IP réelle via Cloudflare
   ?? $_SERVER['HTTP_X_FORWARDED_FOR']
   ?? $_SERVER['REMOTE_ADDR']
   ?? '';

if (!verifierTurnstile($cfToken, CF_TURNSTILE_SECRET, $ip)) {
    http_response_code(403);
    exit(json_encode(['success' => false, 'message' => 'Vérification anti-robot échouée. Veuillez réessayer.']));
}

// ── 8. Protection anti-injection d'en-têtes ──
// (les champs ont déjà été nettoyés, on vérifie qu'aucun contient \r ou \n)
foreach ([$prenom, $nom, $email, $telephone] as $champ) {
    if (preg_match('/[\r\n]/', $champ)) {
        http_response_code(400);
        exit(json_encode(['success' => false, 'message' => 'Données invalides.']));
    }
}

// ── 9. Construction du mail ───────────────────
$nomComplet = $prenom . ' ' . $nom;
$sujet      = MAIL_SUJET_PREFIX . ' Nouvelle demande — ' . $typeExpert . ' — ' . $nomComplet;

$corps = <<<MAIL
Nouvelle demande d'expertise reçue via le site yazgoren-expert.fr
══════════════════════════════════════════════════════════════════

▶ CONTACT
   Nom complet   : {$nomComplet}
   Téléphone     : {$telephone}
   Email         : {$email}

▶ MISSION
   Type          : {$typeExpert}
   Adresse bien  : {$adresseBien}
   Superficie    : {$superficie}

▶ DESCRIPTION
{$description}

──────────────────────────────────────────────────────────────────
Envoyé le : {$_SERVER['REQUEST_TIME_FLOAT']}
IP        : {$ip}
══════════════════════════════════════════════════════════════════
MAIL;

// ── 10. En-têtes du mail ─────────────────────
$headersReply = '';
if (!empty($email)) {
    $headersReply = "Reply-To: {$nomComplet} <{$email}>\r\n";
}

$headers  = "From: " . MAIL_EXPEDITEUR_FROM . "\r\n";
$headers .= $headersReply;
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "Content-Transfer-Encoding: 8bit\r\n";
$headers .= "X-Mailer: PHP/" . PHP_VERSION . "\r\n";

// ── 11. Envoi ─────────────────────────────────
$envoye = mail(MAIL_DESTINATAIRE, $sujet, $corps, $headers);

if ($envoye) {
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => 'Votre demande a bien été envoyée. Je vous réponds sous 24h.'
    ]);
} else {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Une erreur technique est survenue. Veuillez réessayer ou appeler directement.'
    ]);
}
