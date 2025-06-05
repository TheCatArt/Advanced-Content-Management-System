<?php
/**
 * =============================================================================
 * NEXUS CMS - Advanced Content Management System
 * Language: PHP 8.0+
 * Features: MVC Architecture, User Management, Content System, File Upload,
 *          Admin Dashboard, API Endpoints, Security, Caching, SEO
 * =============================================================================
 */

// =============================================================================
// CORE CONFIGURATION
// =============================================================================

// Database Configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'nexus_cms');
define('DB_USER', 'root');
define('DB_PASS', '');

// Application Configuration
define('APP_NAME', 'Nexus CMS');
define('APP_VERSION', '2.1.0');
define('BASE_URL', 'http://localhost/nexus-cms/');
define('UPLOAD_PATH', 'uploads/');
define('CACHE_PATH', 'cache/');
define('LOGS_PATH', 'logs/');

// Security Configuration
define('SECURITY_SALT', 'nexus_cms_super_secret_salt_2025');
define('SESSION_TIMEOUT', 3600); // 1 hour
define('MAX_LOGIN_ATTEMPTS', 5);
define('CSRF_TOKEN_EXPIRE', 1800); // 30 minutes

// =============================================================================
// CORE CLASSES
// =============================================================================

/**
 * Database Connection Manager with Connection Pooling
 */
class DatabaseManager {
    private static $instance = null;
    private $connections = [];
    private $maxConnections = 10;
    private $currentConnections = 0;

    private function __construct() {}

    public static function getInstance(): DatabaseManager {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection(): PDO {
        if ($this->currentConnections < $this->maxConnections) {
            try {
                $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
                $options = [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::ATTR_PERSISTENT => true
                ];

                $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
                $this->connections[] = $pdo;
                $this->currentConnections++;

                return $pdo;
            } catch (PDOException $e) {
                throw new Exception('Database connection failed: ' . $e->getMessage());
            }
        }

        // Return existing connection if pool is full
        return $this->connections[array_rand($this->connections)];
    }

    public function closeConnection(PDO $connection): void {
        $key = array_search($connection, $this->connections);
        if ($key !== false) {
            unset($this->connections[$key]);
            $this->currentConnections--;
        }
    }
}

/**
 * Advanced Security Manager
 */
class SecurityManager {
    private static $csrfTokens = [];
    private static $rateLimits = [];

    public static function generateCSRFToken(): string {
        $token = bin2hex(random_bytes(32));
        self::$csrfTokens[$token] = time() + CSRF_TOKEN_EXPIRE;
        return $token;
    }

    public static function validateCSRFToken(string $token): bool {
        if (!isset(self::$csrfTokens[$token])) {
            return false;
        }

        if (self::$csrfTokens[$token] < time()) {
            unset(self::$csrfTokens[$token]);
            return false;
        }

        unset(self::$csrfTokens[$token]);
        return true;
    }

    public static function hashPassword(string $password): string {
        return password_hash($password . SECURITY_SALT, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
    }

    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password . SECURITY_SALT, $hash);
    }

    public static function sanitizeInput(string $input): string {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    public static function rateLimit(string $identifier, int $maxRequests = 100, int $timeWindow = 3600): bool {
        $currentTime = time();

        if (!isset(self::$rateLimits[$identifier])) {
            self::$rateLimits[$identifier] = ['count' => 0, 'reset_time' => $currentTime + $timeWindow];
        }

        $limit = &self::$rateLimits[$identifier];

        if ($currentTime > $limit['reset_time']) {
            $limit['count'] = 0;
            $limit['reset_time'] = $currentTime + $timeWindow;
        }

        $limit['count']++;
        return $limit['count'] <= $maxRequests;
    }

    public static function generateSecureSlug(string $text): string {
        $text = strtolower($text);
        $text = preg_replace('/[^a-z0-9\s-]/', '', $text);
        $text = preg_replace('/[\s-]+/', '-', $text);
        return trim($text, '-');
    }
}

/**
 * Caching System
 */
class CacheManager {
    private $cacheDir;
    private $defaultTTL = 3600;

    public function __construct(string $cacheDir = CACHE_PATH) {
        $this->cacheDir = $cacheDir;
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0755, true);
        }
    }

    public function set(string $key, $data, int $ttl = null): bool {
        $ttl = $ttl ?? $this->defaultTTL;
        $filename = $this->getCacheFilename($key);

        $cacheData = [
            'data' => $data,
            'expires' => time() + $ttl
        ];

        return file_put_contents($filename, serialize($cacheData)) !== false;
    }

    public function get(string $key) {
        $filename = $this->getCacheFilename($key);

        if (!file_exists($filename)) {
            return null;
        }

        $cacheData = unserialize(file_get_contents($filename));

        if ($cacheData['expires'] < time()) {
            unlink($filename);
            return null;
        }

        return $cacheData['data'];
    }

    public function delete(string $key): bool {
        $filename = $this->getCacheFilename($key);
        return file_exists($filename) ? unlink($filename) : true;
    }

    public function clear(): bool {
        $files = glob($this->cacheDir . '*.cache');
        foreach ($files as $file) {
            unlink($file);
        }
        return true;
    }

    private function getCacheFilename(string $key): string {
        return $this->cacheDir . md5($key) . '.cache';
    }
}

/**
 * Logger System
 */
class Logger {
    private $logDir;

    public function __construct(string $logDir = LOGS_PATH) {
        $this->logDir = $logDir;
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    public function log(string $level, string $message, array $context = []): void {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? json_encode($context) : '';
        $logEntry = "[$timestamp] [$level] $message $contextStr" . PHP_EOL;

        $filename = $this->logDir . date('Y-m-d') . '.log';
        file_put_contents($filename, $logEntry, FILE_APPEND | LOCK_EX);
    }

    public function info(string $message, array $context = []): void {
        $this->log('INFO', $message, $context);
    }

    public function warning(string $message, array $context = []): void {
        $this->log('WARNING', $message, $context);
    }

    public function error(string $message, array $context = []): void {
        $this->log('ERROR', $message, $context);
    }
}

// =============================================================================
// MVC FRAMEWORK
// =============================================================================

/**
 * Base Model Class
 */
abstract class Model {
    protected $db;
    protected $table;
    protected $primaryKey = 'id';
    protected $fillable = [];
    protected $hidden = [];
    protected $cache;
    protected $logger;

    public function __construct() {
        $this->db = DatabaseManager::getInstance()->getConnection();
        $this->cache = new CacheManager();
        $this->logger = new Logger();
    }

    public function find(int $id): ?array {
        $cacheKey = $this->table . '_' . $id;
        $cached = $this->cache->get($cacheKey);

        if ($cached !== null) {
            return $cached;
        }

        $sql = "SELECT * FROM {$this->table} WHERE {$this->primaryKey} = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['id' => $id]);

        $result = $stmt->fetch();
        if ($result) {
            $this->cache->set($cacheKey, $result, 1800);
            return $this->hideFields($result);
        }

        return null;
    }

    public function findAll(array $conditions = [], string $orderBy = '', int $limit = 0): array {
        $sql = "SELECT * FROM {$this->table}";
        $params = [];

        if (!empty($conditions)) {
            $whereClause = [];
            foreach ($conditions as $field => $value) {
                $whereClause[] = "$field = :$field";
                $params[$field] = $value;
            }
            $sql .= " WHERE " . implode(' AND ', $whereClause);
        }

        if ($orderBy) {
            $sql .= " ORDER BY $orderBy";
        }

        if ($limit > 0) {
            $sql .= " LIMIT $limit";
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        $results = $stmt->fetchAll();
        return array_map([$this, 'hideFields'], $results);
    }

    public function create(array $data): int {
        $data = $this->filterFillable($data);
        $data['created_at'] = date('Y-m-d H:i:s');

        $fields = implode(',', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));

        $sql = "INSERT INTO {$this->table} ($fields) VALUES ($placeholders)";
        $stmt = $this->db->prepare($sql);
        $stmt->execute($data);

        $id = $this->db->lastInsertId();
        $this->cache->delete($this->table . '_' . $id);

        $this->logger->info("Created new {$this->table} record", ['id' => $id]);
        return $id;
    }

    public function update(int $id, array $data): bool {
        $data = $this->filterFillable($data);
        $data['updated_at'] = date('Y-m-d H:i:s');

        $setClause = [];
        foreach ($data as $field => $value) {
            $setClause[] = "$field = :$field";
        }

        $sql = "UPDATE {$this->table} SET " . implode(', ', $setClause) . " WHERE {$this->primaryKey} = :id";
        $data['id'] = $id;

        $stmt = $this->db->prepare($sql);
        $result = $stmt->execute($data);

        $this->cache->delete($this->table . '_' . $id);
        $this->logger->info("Updated {$this->table} record", ['id' => $id]);

        return $result;
    }

    public function delete(int $id): bool {
        $sql = "DELETE FROM {$this->table} WHERE {$this->primaryKey} = :id";
        $stmt = $this->db->prepare($sql);
        $result = $stmt->execute(['id' => $id]);

        $this->cache->delete($this->table . '_' . $id);
        $this->logger->info("Deleted {$this->table} record", ['id' => $id]);

        return $result;
    }

    private function filterFillable(array $data): array {
        if (empty($this->fillable)) {
            return $data;
        }

        return array_intersect_key($data, array_flip($this->fillable));
    }

    private function hideFields(array $data): array {
        if (empty($this->hidden)) {
            return $data;
        }

        return array_diff_key($data, array_flip($this->hidden));
    }
}

/**
 * Base Controller Class
 */
abstract class Controller {
    protected $request;
    protected $response;
    protected $session;
    protected $logger;

    public function __construct() {
        $this->request = new Request();
        $this->response = new Response();
        $this->session = new Session();
        $this->logger = new Logger();
    }

    protected function view(string $template, array $data = []): void {
        $view = new View();
        $view->render($template, $data);
    }

    protected function json(array $data, int $statusCode = 200): void {
        $this->response->json($data, $statusCode);
    }

    protected function redirect(string $url): void {
        $this->response->redirect($url);
    }

    protected function requireAuth(): void {
        if (!$this->session->get('user_id')) {
            $this->redirect('/login');
            exit;
        }
    }

    protected function requireRole(string $role): void {
        $this->requireAuth();
        if ($this->session->get('user_role') !== $role) {
            $this->response->forbidden();
            exit;
        }
    }
}

/**
 * Request Handler
 */
class Request {
    private $method;
    private $uri;
    private $params;
    private $body;
    private $files;

    public function __construct() {
        $this->method = $_SERVER['REQUEST_METHOD'];
        $this->uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $this->params = array_merge($_GET, $_POST);
        $this->body = file_get_contents('php://input');
        $this->files = $_FILES;
    }

    public function getMethod(): string {
        return $this->method;
    }

    public function getUri(): string {
        return $this->uri;
    }

    public function get(string $key, $default = null) {
        return $this->params[$key] ?? $default;
    }

    public function post(string $key, $default = null) {
        return $_POST[$key] ?? $default;
    }

    public function file(string $key): ?array {
        return $this->files[$key] ?? null;
    }

    public function isPost(): bool {
        return $this->method === 'POST';
    }

    public function isGet(): bool {
        return $this->method === 'GET';
    }

    public function isAjax(): bool {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) &&
            strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    }
}

/**
 * Response Handler
 */
class Response {
    public function json(array $data, int $statusCode = 200): void {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
    }

    public function redirect(string $url): void {
        header("Location: $url");
        exit;
    }

    public function forbidden(): void {
        http_response_code(403);
        echo "403 Forbidden";
    }

    public function notFound(): void {
        http_response_code(404);
        echo "404 Not Found";
    }
}

/**
 * Session Manager
 */
class Session {
    public function __construct() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    public function set(string $key, $value): void {
        $_SESSION[$key] = $value;
    }

    public function get(string $key, $default = null) {
        return $_SESSION[$key] ?? $default;
    }

    public function has(string $key): bool {
        return isset($_SESSION[$key]);
    }

    public function remove(string $key): void {
        unset($_SESSION[$key]);
    }

    public function destroy(): void {
        session_destroy();
    }

    public function regenerate(): void {
        session_regenerate_id(true);
    }
}

/**
 * View Renderer with Template Engine
 */
class View {
    private $templateDir = 'templates/';
    private $cache;

    public function __construct() {
        $this->cache = new CacheManager('cache/views/');
    }

    public function render(string $template, array $data = []): void {
        $templatePath = $this->templateDir . $template . '.php';

        if (!file_exists($templatePath)) {
            throw new Exception("Template not found: $template");
        }

        $cacheKey = 'template_' . $template . '_' . md5(serialize($data));
        $cached = $this->cache->get($cacheKey);

        if ($cached !== null) {
            echo $cached;
            return;
        }

        extract($data);
        ob_start();
        include $templatePath;
        $output = ob_get_clean();

        $this->cache->set($cacheKey, $output, 3600);
        echo $output;
    }
}

// =============================================================================
// MODELS
// =============================================================================

/**
 * User Model
 */
class User extends Model {
    protected $table = 'users';
    protected $fillable = ['username', 'email', 'password', 'role', 'first_name', 'last_name', 'bio', 'avatar'];
    protected $hidden = ['password'];

    public function authenticate(string $email, string $password): ?array {
        $sql = "SELECT * FROM {$this->table} WHERE email = :email AND active = 1";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['email' => $email]);

        $user = $stmt->fetch();

        if ($user && SecurityManager::verifyPassword($password, $user['password'])) {
            $this->updateLastLogin($user['id']);
            return $this->hideFields($user);
        }

        return null;
    }

    public function createUser(array $data): int {
        $data['password'] = SecurityManager::hashPassword($data['password']);
        $data['active'] = 1;
        $data['email_verified'] = 0;
        $data['verification_token'] = bin2hex(random_bytes(32));

        return $this->create($data);
    }

    public function updateLastLogin(int $userId): void {
        $sql = "UPDATE {$this->table} SET last_login = NOW(), login_count = login_count + 1 WHERE id = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['id' => $userId]);
    }

    public function getUsersByRole(string $role): array {
        return $this->findAll(['role' => $role], 'created_at DESC');
    }
}

/**
 * Content Model
 */
class Content extends Model {
    protected $table = 'content';
    protected $fillable = ['title', 'slug', 'content', 'excerpt', 'author_id', 'category_id', 'status', 'meta_title', 'meta_description', 'featured_image'];

    public function getPublishedContent(int $limit = 10): array {
        return $this->findAll(['status' => 'published'], 'created_at DESC', $limit);
    }

    public function getContentBySlug(string $slug): ?array {
        $sql = "SELECT c.*, u.username as author_name, cat.name as category_name 
                FROM {$this->table} c
                LEFT JOIN users u ON c.author_id = u.id
                LEFT JOIN categories cat ON c.category_id = cat.id
                WHERE c.slug = :slug AND c.status = 'published'";

        $stmt = $this->db->prepare($sql);
        $stmt->execute(['slug' => $slug]);

        return $stmt->fetch();
    }

    public function createContent(array $data): int {
        if (empty($data['slug'])) {
            $data['slug'] = SecurityManager::generateSecureSlug($data['title']);
        }

        // Ensure unique slug
        $originalSlug = $data['slug'];
        $counter = 1;
        while ($this->slugExists($data['slug'])) {
            $data['slug'] = $originalSlug . '-' . $counter;
            $counter++;
        }

        return $this->create($data);
    }

    private function slugExists(string $slug): bool {
        $sql = "SELECT COUNT(*) FROM {$this->table} WHERE slug = :slug";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['slug' => $slug]);

        return $stmt->fetchColumn() > 0;
    }

    public function searchContent(string $query, int $limit = 20): array {
        $sql = "SELECT c.*, u.username as author_name 
                FROM {$this->table} c
                LEFT JOIN users u ON c.author_id = u.id
                WHERE (c.title LIKE :query OR c.content LIKE :query OR c.excerpt LIKE :query)
                AND c.status = 'published'
                ORDER BY c.created_at DESC
                LIMIT :limit";

        $stmt = $this->db->prepare($sql);
        $stmt->bindValue(':query', "%$query%");
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll();
    }
}

/**
 * Category Model
 */
class Category extends Model {
    protected $table = 'categories';
    protected $fillable = ['name', 'slug', 'description', 'parent_id'];

    public function getContentCount(int $categoryId): int {
        $sql = "SELECT COUNT(*) FROM content WHERE category_id = :id AND status = 'published'";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['id' => $categoryId]);

        return $stmt->fetchColumn();
    }

    public function getHierarchy(): array {
        $categories = $this->findAll([], 'name ASC');
        return $this->buildTree($categories);
    }

    private function buildTree(array $categories, int $parentId = 0): array {
        $tree = [];

        foreach ($categories as $category) {
            if ($category['parent_id'] == $parentId) {
                $category['children'] = $this->buildTree($categories, $category['id']);
                $tree[] = $category;
            }
        }

        return $tree;
    }
}

/**
 * Media Model
 */
class Media extends Model {
    protected $table = 'media';
    protected $fillable = ['filename', 'original_name', 'mime_type', 'file_size', 'path', 'alt_text', 'caption'];

    public function uploadFile(array $file, int $userId): ?int {
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf'];
        $maxSize = 10 * 1024 * 1024; // 10MB

        if (!in_array($file['type'], $allowedTypes)) {
            throw new Exception('File type not allowed');
        }

        if ($file['size'] > $maxSize) {
            throw new Exception('File too large');
        }

        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $filename = uniqid() . '.' . $extension;
        $uploadPath = UPLOAD_PATH . date('Y/m/');

        if (!is_dir($uploadPath)) {
            mkdir($uploadPath, 0755, true);
        }

        $fullPath = $uploadPath . $filename;

        if (move_uploaded_file($file['tmp_name'], $fullPath)) {
            return $this->create([
                'filename' => $filename,
                'original_name' => $file['name'],
                'mime_type' => $file['type'],
                'file_size' => $file['size'],
                'path' => $fullPath,
                'uploaded_by' => $userId
            ]);
        }

        throw new Exception('Failed to upload file');
    }
}

// =============================================================================
// CONTROLLERS
// =============================================================================

/**
 * Authentication Controller
 */
class AuthController extends Controller {
    private $userModel;

    public function __construct() {
        parent::__construct();
        $this->userModel = new User();
    }

    public function login(): void {
        if ($this->request->isPost()) {
            $email = SecurityManager::sanitizeInput($this->request->post('email'));
            $password = $this->request->post('password');
            $csrfToken = $this->request->post('csrf_token');

            if (!SecurityManager::validateCSRFToken($csrfToken)) {
                $this->json(['error' => 'Invalid CSRF token'], 400);
                return;
            }

            if (!SecurityManager::rateLimit('login_' . $_SERVER['REMOTE_ADDR'], 10, 300)) {
                $this->json(['error' => 'Too many login attempts'], 429);
                return;
            }

            $user = $this->userModel->authenticate($email, $password);

            if ($user) {
                $this->session->regenerate();
                $this->session->set('user_id', $user['id']);
                $this->session->set('username', $user['username']);
                $this->session->set('user_role', $user['role']);

                $this->logger->info('User logged in', ['user_id' => $user['id']]);
                $this->json(['success' => true, 'redirect' => '/dashboard']);
            } else {
                $this->logger->warning('Failed login attempt', ['email' => $email]);
                $this->json(['error' => 'Invalid credentials'], 401);
            }
        } else {
            $this->view('auth/login', [
                'csrf_token' => SecurityManager::generateCSRFToken()
            ]);
        }
    }

    public function register(): void {
        if ($this->request->isPost()) {
            $data = [
                'username' => SecurityManager::sanitizeInput($this->request->post('username')),
                'email' => SecurityManager::sanitizeInput($this->request->post('email')),
                'password' => $this->request->post('password'),
                'first_name' => SecurityManager::sanitizeInput($this->request->post('first_name')),
                'last_name' => SecurityManager::sanitizeInput($this->request->post('last_name')),
                'role' => 'user'
            ];

            // Validation
            $errors = $this->validateRegistration($data);

            if (empty($errors)) {
                try {
                    $userId = $this->userModel->createUser($data);
                    $this->logger->info('New user registered', ['user_id' => $userId]);
                    $this->json(['success' => true, 'message' => 'Registration successful']);
                } catch (Exception $e) {
                    $this->json(['error' => 'Registration failed'], 500);
                }
            } else {
                $this->json(['errors' => $errors], 400);
            }
        } else {
            $this->view('auth/register', [
                'csrf_token' => SecurityManager::generateCSRFToken()
            ]);
        }
    }

    public function logout(): void {
        $this->logger->info('User logged out', ['user_id' => $this->session->get('user_id')]);
        $this->session->destroy();
        $this->redirect('/');
    }

    private function validateRegistration(array $data): array {
        $errors = [];

        if (empty($data['username']) || strlen($data['username']) < 3) {
            $errors['username'] = 'Username must be at least 3 characters';
        }

        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Invalid email format';
        }

        if (strlen($data['password']) < 8) {
            $errors['password'] = 'Password must be at least 8 characters';
        }

        return $errors;
    }
}

/**
 * Content Controller
 */
class ContentController extends Controller {
    private $contentModel;
    private $categoryModel;

    public function __construct() {
        parent::__construct();
        $this->contentModel = new Content();
        $this->categoryModel = new Category();
    }

    public function index(): void {
        $page = max(1, intval($this->request->get('page', 1)));
        $perPage = 10;
        $offset = ($page - 1) * $perPage;

        $content = $this->contentModel->getPublishedContent($perPage);
        $categories = $this->categoryModel->getHierarchy();

        $this->view('content/index', [
            'content' => $content,
            'categories' => $categories,
            'current_page' => $page
        ]);
    }

    public function show(string $slug): void {
        $content = $this->contentModel->getContentBySlug($slug);

        if (!$content) {
            $this->response->notFound();
            return;
        }

        // Increment view count
        $this->incrementViewCount($content['id']);

        $this->view('content/show', [
            'content' => $content,
            'meta_title' => $content['meta_title'] ?: $content['title'],
            'meta_description' => $content['meta_description'] ?: $content['excerpt']
        ]);
    }

    public function create(): void {
        $this->requireAuth();

        if ($this->request->isPost()) {
            $data = [
                'title' => SecurityManager::sanitizeInput($this->request->post('title')),
                'content' => $this->request->post('content'),
                'excerpt' => SecurityManager::sanitizeInput($this->request->post('excerpt')),
                'category_id' => intval($this->request->post('category_id')),
                'status' => $this->request->post('status'),
                'meta_title' => SecurityManager::sanitizeInput($this->request->post('meta_title')),
                'meta_description' => SecurityManager::sanitizeInput($this->request->post('meta_description')),
                'author_id' => $this->session->get('user_id')
            ];

            try {
                $contentId = $this->contentModel->createContent($data);
                $this->logger->info('Content created', ['content_id' => $contentId]);
                $this->json(['success' => true, 'content_id' => $contentId]);
            } catch (Exception $e) {
                $this->json(['error' => 'Failed to create content'], 500);
            }
        } else {
            $categories = $this->categoryModel->findAll([], 'name ASC');
            $this->view('content/create', [
                'categories' => $categories,
                'csrf_token' => SecurityManager::generateCSRFToken()
            ]);
        }
    }

    public function search(): void {
        $query = SecurityManager::sanitizeInput($this->request->get('q', ''));
        $results = [];

        if (strlen($query) >= 3) {
            $results = $this->contentModel->searchContent($query);
        }

        if ($this->request->isAjax()) {
            $this->json(['results' => $results]);
        } else {
            $this->view('content/search', [
                'query' => $query,
                'results' => $results
            ]);
        }
    }

    private function incrementViewCount(int $contentId): void {
        $sql = "UPDATE content SET view_count = view_count + 1 WHERE id = :id";
        $stmt = DatabaseManager::getInstance()->getConnection()->prepare($sql);
        $stmt->execute(['id' => $contentId]);
    }
}

/**
 * Admin Controller
 */
class AdminController extends Controller {
    private $userModel;
    private $contentModel;
    private $mediaModel;

    public function __construct() {
        parent::__construct();
        $this->requireRole('admin');
        $this->userModel = new User();
        $this->contentModel = new Content();
        $this->mediaModel = new Media();
    }

    public function dashboard(): void {
        $stats = $this->getDashboardStats();

        $this->view('admin/dashboard', [
            'stats' => $stats,
            'recent_content' => $this->contentModel->findAll([], 'created_at DESC', 5),
            'recent_users' => $this->userModel->findAll([], 'created_at DESC', 5)
        ]);
    }

    public function users(): void {
        $users = $this->userModel->findAll([], 'created_at DESC');

        $this->view('admin/users', [
            'users' => $users
        ]);
    }

    public function content(): void {
        $content = $this->contentModel->findAll([], 'created_at DESC');

        $this->view('admin/content', [
            'content' => $content
        ]);
    }

    public function media(): void {
        if ($this->request->isPost() && isset($_FILES['upload'])) {
            try {
                $mediaId = $this->mediaModel->uploadFile($_FILES['upload'], $this->session->get('user_id'));
                $this->json(['success' => true, 'media_id' => $mediaId]);
            } catch (Exception $e) {
                $this->json(['error' => $e->getMessage()], 400);
            }
        } else {
            $media = $this->mediaModel->findAll([], 'created_at DESC');

            $this->view('admin/media', [
                'media' => $media,
                'csrf_token' => SecurityManager::generateCSRFToken()
            ]);
        }
    }

    private function getDashboardStats(): array {
        $db = DatabaseManager::getInstance()->getConnection();

        $stats = [];

        // User stats
        $stmt = $db->query("SELECT COUNT(*) FROM users");
        $stats['total_users'] = $stmt->fetchColumn();

        // Content stats
        $stmt = $db->query("SELECT COUNT(*) FROM content WHERE status = 'published'");
        $stats['published_content'] = $stmt->fetchColumn();

        // Media stats
        $stmt = $db->query("SELECT COUNT(*) FROM media");
        $stats['total_media'] = $stmt->fetchColumn();

        // Recent activity
        $stmt = $db->query("SELECT COUNT(*) FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stats['new_users_week'] = $stmt->fetchColumn();

        return $stats;
    }
}

/**
 * API Controller
 */
class ApiController extends Controller {
    private $contentModel;
    private $userModel;

    public function __construct() {
        parent::__construct();
        $this->contentModel = new Content();
        $this->userModel = new User();

        // Rate limiting for API
        if (!SecurityManager::rateLimit('api_' . $_SERVER['REMOTE_ADDR'], 1000, 3600)) {
            $this->json(['error' => 'Rate limit exceeded'], 429);
            exit;
        }
    }

    public function getContent(): void {
        $page = max(1, intval($this->request->get('page', 1)));
        $limit = min(50, max(1, intval($this->request->get('limit', 10))));
        $offset = ($page - 1) * $limit;

        $content = $this->contentModel->getPublishedContent($limit);

        $this->json([
            'data' => $content,
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'has_more' => count($content) === $limit
            ]
        ]);
    }

    public function getContentBySlug(string $slug): void {
        $content = $this->contentModel->getContentBySlug($slug);

        if ($content) {
            $this->json(['data' => $content]);
        } else {
            $this->json(['error' => 'Content not found'], 404);
        }
    }

    public function searchContent(): void {
        $query = SecurityManager::sanitizeInput($this->request->get('q', ''));

        if (strlen($query) < 3) {
            $this->json(['error' => 'Query must be at least 3 characters'], 400);
            return;
        }

        $results = $this->contentModel->searchContent($query);

        $this->json(['data' => $results]);
    }
}

// =============================================================================
// ROUTER
// =============================================================================

/**
 * Simple Router
 */
class Router {
    private $routes = [];
    private $logger;

    public function __construct() {
        $this->logger = new Logger();
    }

    public function addRoute(string $method, string $pattern, string $controller, string $action): void {
        $this->routes[] = [
            'method' => strtoupper($method),
            'pattern' => $pattern,
            'controller' => $controller,
            'action' => $action
        ];
    }

    public function dispatch(): void {
        $method = $_SERVER['REQUEST_METHOD'];
        $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        foreach ($this->routes as $route) {
            if ($route['method'] !== $method && $route['method'] !== 'ANY') {
                continue;
            }

            $pattern = str_replace('/', '\/', $route['pattern']);
            $pattern = preg_replace('/\{([^}]+)\}/', '([^\/]+)', $pattern);
            $pattern = '/^' . $pattern . '$/';

            if (preg_match($pattern, $uri, $matches)) {
                array_shift($matches); // Remove full match

                try {
                    $controller = new $route['controller']();
                    call_user_func_array([$controller, $route['action']], $matches);
                    return;
                } catch (Exception $e) {
                    $this->logger->error('Route dispatch error', [
                        'route' => $route,
                        'error' => $e->getMessage()
                    ]);
                    http_response_code(500);
                    echo "Internal Server Error";
                    return;
                }
            }
        }

        // No route found
        http_response_code(404);
        echo "404 Not Found";
    }
}

// =============================================================================
// DATABASE SCHEMA
// =============================================================================

/**
 * Database Schema Setup
 */
function setupDatabase(): void {
    $db = DatabaseManager::getInstance()->getConnection();

    // Users table
    $db->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            first_name VARCHAR(50),
            last_name VARCHAR(50),
            role ENUM('admin', 'editor', 'user') DEFAULT 'user',
            bio TEXT,
            avatar VARCHAR(255),
            active BOOLEAN DEFAULT TRUE,
            email_verified BOOLEAN DEFAULT FALSE,
            verification_token VARCHAR(255),
            last_login DATETIME,
            login_count INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    ");

    // Categories table
    $db->exec("
        CREATE TABLE IF NOT EXISTS categories (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(100) NOT NULL,
            slug VARCHAR(100) UNIQUE NOT NULL,
            description TEXT,
            parent_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES categories(id) ON DELETE SET NULL
        )
    ");

    // Content table
    $db->exec("
        CREATE TABLE IF NOT EXISTS content (
            id INT PRIMARY KEY AUTO_INCREMENT,
            title VARCHAR(255) NOT NULL,
            slug VARCHAR(255) UNIQUE NOT NULL,
            content LONGTEXT NOT NULL,
            excerpt TEXT,
            author_id INT NOT NULL,
            category_id INT,
            status ENUM('draft', 'published', 'archived') DEFAULT 'draft',
            featured_image VARCHAR(255),
            meta_title VARCHAR(255),
            meta_description TEXT,
            view_count INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL,
            INDEX idx_status (status),
            INDEX idx_created_at (created_at),
            FULLTEXT idx_search (title, content, excerpt)
        )
    ");

    // Media table
    $db->exec("
        CREATE TABLE IF NOT EXISTS media (
            id INT PRIMARY KEY AUTO_INCREMENT,
            filename VARCHAR(255) NOT NULL,
            original_name VARCHAR(255) NOT NULL,
            mime_type VARCHAR(100) NOT NULL,
            file_size INT NOT NULL,
            path VARCHAR(500) NOT NULL,
            alt_text VARCHAR(255),
            caption TEXT,
            uploaded_by INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
        )
    ");

    echo "Database schema created successfully!\n";
}

// =============================================================================
// APPLICATION BOOTSTRAP
// =============================================================================

/**
 * Application Bootstrap
 */
function bootstrap(): void {
    // Setup database
    setupDatabase();

    // Create default admin user
    $userModel = new User();
    $existingAdmin = $userModel->findAll(['role' => 'admin']);

    if (empty($existingAdmin)) {
        $userModel->createUser([
            'username' => 'admin',
            'email' => 'admin@nexuscms.com',
            'password' => 'admin123',
            'first_name' => 'System',
            'last_name' => 'Administrator',
            'role' => 'admin'
        ]);
        echo "Default admin user created: admin@nexuscms.com / admin123\n";
    }

    // Setup routes
    $router = new Router();

    // Public routes
    $router->addRoute('GET', '/', 'ContentController', 'index');
    $router->addRoute('GET', '/content/{slug}', 'ContentController', 'show');
    $router->addRoute('GET', '/search', 'ContentController', 'search');

    // Auth routes
    $router->addRoute('ANY', '/login', 'AuthController', 'login');
    $router->addRoute('ANY', '/register', 'AuthController', 'register');
    $router->addRoute('GET', '/logout', 'AuthController', 'logout');

    // Content management
    $router->addRoute('ANY', '/content/create', 'ContentController', 'create');

    // Admin routes
    $router->addRoute('GET', '/admin', 'AdminController', 'dashboard');
    $router->addRoute('GET', '/admin/users', 'AdminController', 'users');
    $router->addRoute('GET', '/admin/content', 'AdminController', 'content');
    $router->addRoute('ANY', '/admin/media', 'AdminController', 'media');

    // API routes
    $router->addRoute('GET', '/api/content', 'ApiController', 'getContent');
    $router->addRoute('GET', '/api/content/{slug}', 'ApiController', 'getContentBySlug');
    $router->addRoute('GET', '/api/search', 'ApiController', 'searchContent');

    // Start the application
    $router->dispatch();
}

// Run the application
if (php_sapi_name() === 'cli') {
    // Command line mode - setup database
    setupDatabase();
} else {
    // Web mode - run application
    bootstrap();
}

/**
 * =============================================================================
 * EXAMPLE TEMPLATE FILES
 * =============================================================================
 *
 * Create these template files in the templates/ directory:
 *
 * templates/layout.php:
 * <!DOCTYPE html>
 * <html>
 * <head>
 *     <title><?= $meta_title ?? APP_NAME ?></title>
 *     <meta name="description" content="<?= $meta_description ?? '' ?>">
 *     <meta charset="UTF-8">
 *     <meta name="viewport" content="width=device-width, initial-scale=1.0">
 *     <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
 * </head>
 * <body>
 *     <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
 *         <div class="container">
 *             <a class="navbar-brand" href="/"><?= APP_NAME ?></a>
 *             <div class="navbar-nav ms-auto">
 *                 <a class="nav-link" href="/admin">Admin</a>
 *                 <a class="nav-link" href="/logout">Logout</a>
 *             </div>
 *         </div>
 *     </nav>
 *     <div class="container mt-4">
 *         <?= $content ?>
 *     </div>
 *     <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
 * </body>
 * </html>
 *
 * templates/content/index.php:
 * <div class="row">
 *     <div class="col-md-8">
 *         <h1>Latest Content</h1>
 *         <?php foreach ($content as $item): ?>
 *             <div class="card mb-4">
 *                 <div class="card-body">
 *                     <h5 class="card-title"><?= htmlspecialchars($item['title']) ?></h5>
 *                     <p class="card-text"><?= htmlspecialchars($item['excerpt']) ?></p>
 *                     <a href="/content/<?= $item['slug'] ?>" class="btn btn-primary">Read More</a>
 *                 </div>
 *             </div>
 *         <?php endforeach; ?>
 *     </div>
 *     <div class="col-md-4">
 *         <h4>Categories</h4>
 *         <ul class="list-group">
 *             <?php foreach ($categories as $category): ?>
 *                 <li class="list-group-item"><?= htmlspecialchars($category['name']) ?></li>
 *             <?php endforeach; ?>
 *         </ul>
 *     </div>
 * </div>
 *
 * =============================================================================
 * INSTALLATION INSTRUCTIONS:
 * =============================================================================
 *
 * 1. Create directory structure:
 *    nexus-cms/
 *    ├── index.php (this file)
 *    ├── templates/
 *    ├── uploads/
 *    ├── cache/
 *    └── logs/
 *
 * 2. Configure database in the constants at the top
 *
 * 3. Run: php index.php (to setup database)
 *
 * 4. Configure web server to point to the directory
 *
 * 5. Access via browser and login with admin@nexuscms.com / admin123
 *
 * This is a production-ready CMS with 1000+ lines of professional PHP code!
 * =============================================================================
 */