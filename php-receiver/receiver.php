<?php
// AdaptXSS PHP Fallback Receiver
// Requirement: PHP 8.0+, write permission on store/ directory

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$raw = file_get_contents('php://input');
$data = json_decode($raw, true);

if (!$data || !isset($data['sessionId'], $data['probability'], $data['label'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid payload']);
    exit;
}

// Validate probability range
if ($data['probability'] < 0 || $data['probability'] > 1) {
    http_response_code(400);
    echo json_encode(['error' => 'probability out of range']);
    exit;
}

$data['received_at'] = time();
$store_file = __DIR__ . '/store/events.json';

// Append to JSON lines file (one JSON object per line)
$line = json_encode($data) . PHP_EOL;
$fp = fopen($store_file, 'a');
if (!$fp) {
    http_response_code(500);
    echo json_encode(['error' => 'Cannot write to store']);
    exit;
}
fwrite($fp, $line);
fclose($fp);

http_response_code(201);
echo json_encode(['ok' => true]);
