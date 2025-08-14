<?php
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

/**
 * IP智能内容控制插件 - 根据用户IP自动显示或隐藏内容
 * 
 * @package IPAuth
 * @author fqbin
 * @version 1.0.0
 * @link https://github.com/fqbin/IPAuth
 */
class IPAuth_Plugin implements Typecho_Plugin_Interface
{
    private static $ipCache = null;
    
    /**
     * Activate plugin method
     */
    public static function activate()
    {
        // Register content filter hook
        Typecho_Plugin::factory('Widget_Abstract_Contents')->contentEx = array('IPAuth_Plugin', 'contentFilter');
        Typecho_Plugin::factory('Widget_Abstract_Contents')->excerptEx = array('IPAuth_Plugin', 'contentFilter');
        
        return '插件启用成功！系统将根据访问者IP自动显示或隐藏受保护内容。使用 [ipauth]内容[/ipauth] 标记需要IP控制的内容。';
    }

    /**
     * Deactivate plugin method
     */
    public static function deactivate()
    {
        return '插件已禁用';
    }

    /**
     * Get plugin configuration panel
     * 
     * @param Typecho_Widget_Helper_Form $form
     */
    public static function config(Typecho_Widget_Helper_Form $form)
    {
        // Authorized IP list configuration
        $authorizedIPs = new Typecho_Widget_Helper_Form_Element_Textarea(
            'authorizedIPs', 
            NULL, 
            "127.0.0.1\n::1\n192.168.1.0/24", 
            _t('授权IP列表'), 
            _t('每行一个IP地址，支持IPv4和CIDR格式。例如：192.168.1.100 或 192.168.1.0/24')
        );
        $form->addInput($authorizedIPs);

        // Control mode configuration
        $controlMode = new Typecho_Widget_Helper_Form_Element_Radio(
            'controlMode',
            array(
                'whitelist' => _t('白名单模式 - 只有授权IP可见受保护内容'),
                'blacklist' => _t('黑名单模式 - 授权IP不可见受保护内容')
            ),
            'whitelist',
            _t('IP控制模式'),
            _t('选择IP控制的工作方式')
        );
        $form->addInput($controlMode);

        $logoUrl = new Typecho_Widget_Helper_Form_Element_Text(
            'logoUrl',
            NULL,
            '',
            _t('提示框Logo URL'),
            _t('隐藏内容提示框的Logo图片URL，留空使用默认图标。请确保URL来源可信，避免使用不安全的外部链接。')
        );
        $form->addInput($logoUrl);

        // Prompt text configuration
        $customText = new Typecho_Widget_Helper_Form_Element_Text(
            'customText',
            NULL,
            '此区域的内容仅允许通过南方医科大学校内 IP 进行访问，请首先登入校园网环境。',
            _t('提示文字'),
            _t('隐藏内容的提示文字')
        );
        $form->addInput($customText);

        // Background color configuration
        $backgroundColor = new Typecho_Widget_Helper_Form_Element_Text(
            'backgroundColor',
            NULL,
            '#f0f9ec',
            _t('背景颜色'),
            _t('提示框背景颜色，格式：#fef8f8')
        );
        $form->addInput($backgroundColor);

        // Theme color configuration (border and text color)
        $themeColor = new Typecho_Widget_Helper_Form_Element_Text(
            'themeColor',
            NULL,
            '#78C841',
            _t('主题颜色'),
            _t('提示框边框、图标和文字颜色，格式：#a31c1c')
        );
        $form->addInput($themeColor);

        $detectExternalIP = new Typecho_Widget_Helper_Form_Element_Radio(
            'detectExternalIP',
            array('1' => _t('启用'), '0' => _t('禁用')),
            '0',
            _t('外网IP检测'),
            _t('启用后会同时检测外网IP地址。警告：此功能可能存在安全风险，建议仅在必要时启用。')
        );
        $form->addInput($detectExternalIP);

        // Debug mode
        $debugMode = new Typecho_Widget_Helper_Form_Element_Radio(
            'debugMode',
            array('1' => _t('启用'), '0' => _t('禁用')),
            '0',
            _t('调试模式'),
            _t('启用后会在页面底部显示当前访问者IP地址（仅管理员可见）')
        );
        $form->addInput($debugMode);
    }

    /**
     * Personal user configuration panel
     * 
     * @param Typecho_Widget_Helper_Form $form
     */
    public static function personalConfig(Typecho_Widget_Helper_Form $form) {}

    /**
     * Validate and sanitize URL input
     * 
     * @param string $url
     * @return string
     */
    private static function sanitizeUrl($url)
    {
        if (empty($url)) {
            return '';
        }
        
        // Basic URL sanitization
        $url = filter_var(trim($url), FILTER_SANITIZE_URL);
        
        // Validate URL format
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return '';
        }
        
        // Only allow HTTP and HTTPS protocols
        $parsed = parse_url($url);
        if (!isset($parsed['scheme']) || !in_array($parsed['scheme'], ['http', 'https'])) {
            return '';
        }
        
        return $url;
    }
    
    /**
     * Validate and sanitize color value
     * 
     * @param string $color
     * @param string $default
     * @return string
     */
    private static function sanitizeColor($color, $default = '#000000')
    {
        if (empty($color)) {
            return $default;
        }
        
        // Validate hexadecimal color format
        if (preg_match('/^#[0-9A-Fa-f]{6}$/', $color)) {
            return $color;
        }
        
        return $default;
    }

    /**
     * Get user's real IP address (Security Enhanced Version)
     * 
     * @return array Returns local IP and external IP
     */
    private static function getRealIP()
    {
        if (self::$ipCache !== null) {
            return self::$ipCache;
        }
        
        $localIP = '';
        $externalIP = '';
        
        // Priority order: Trusted proxy headers > Standard headers > REMOTE_ADDR
        $trustHeaders = array(
            'HTTP_CF_CONNECTING_IP',     // Cloudflare (most trusted)
            'HTTP_X_REAL_IP',           // Nginx proxy
            'HTTP_TRUE_CLIENT_IP',      // Akamai/Cloudflare
            'HTTP_X_FORWARDED_FOR'      // Standard proxy header (least trusted)
        );
        
        foreach ($trustHeaders as $header) {
            if (!empty($_SERVER[$header])) {
                $headerValue = $_SERVER[$header];
                
                // Handle X-Forwarded-For which may contain multiple IPs
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $ips = array_map('trim', explode(',', $headerValue));
                    $headerValue = $ips[0]; // Take the first IP
                }
                
                // Validate IP format and exclude private IPs
                if (filter_var($headerValue, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $localIP = $headerValue;
                    break;
                }
            }
        }
        
        // If no valid public IP found, use REMOTE_ADDR
        if (empty($localIP)) {
            $localIP = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        }
        
        // External IP detection (if enabled)
        $options = Typecho_Widget::widget('Widget_Options');
        $pluginOptions = $options->plugin('IPAuth');
        
        if ($pluginOptions && isset($pluginOptions->detectExternalIP) && $pluginOptions->detectExternalIP == '1') {
            $externalIP = self::getExternalIPSafely();
        }
        
        $result = array('local' => $localIP, 'external' => $externalIP);
        self::$ipCache = $result;
        
        return $result;
    }
    
    /**
     * Safe external IP detection method
     * 
     * @return string
     */
    private static function getExternalIPSafely()
    {
        $services = array(
            'https://checkip.amazonaws.com',    // AWS official service (most trusted)
            'https://api.ipify.org',            // Well-known service
        );
        
        $context = stream_context_create([
            'http' => [
                'timeout' => 2,  // Increased to 2 seconds timeout
                'method' => 'GET',
                'header' => [
                    'User-Agent: Typecho IPAuth Plugin/1.1.0',
                    'Accept: text/plain',
                    'Connection: close'
                ],
                'follow_location' => 0,
                'max_redirects' => 0,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
            ]
        ]);
        
        foreach ($services as $service) {
            try {
                $response = @file_get_contents($service, false, $context);
                if ($response !== false) {
                    $ip = trim($response);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            } catch (Exception $e) {
                // Silently handle errors, continue to next service
                continue;
            }
        }
        
        return '';
    }

    /**
     * Check if IP is in the authorized list
     * 
     * @param string $userIP User IP
     * @param array $authorizedIPs Authorized IP list
     * @return bool
     */
    private static function isAuthorizedIP($userIP, $authorizedIPs)
    {
        $userIP = trim($userIP);
        
        if (!filter_var($userIP, FILTER_VALIDATE_IP)) {
            return false;
        }
        
        foreach ($authorizedIPs as $authorizedIP) {
            $authorizedIP = trim($authorizedIP);
            
            if (empty($authorizedIP)) {
                continue;
            }
            
            // Exact match
            if ($userIP === $authorizedIP) {
                return true;
            }
            
            // CIDR format matching (e.g., 192.168.1.0/24)
            if (strpos($authorizedIP, '/') !== false) {
                if (self::ipInRange($userIP, $authorizedIP)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Check if IP is within CIDR range
     * 
     * @param string $ip IP to check
     * @param string $range CIDR formatted IP range
     * @return bool
     */
    private static function ipInRange($ip, $range)
    {
        if (strpos($range, '/') === false) {
            return false;
        }
        
        list($subnet, $bits) = explode('/', $range);
        
        // Validate CIDR format
        if (!is_numeric($bits)) {
            return false;
        }
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4
            $bits = intval($bits);
            if ($bits < 0 || $bits > 32) {
                return false;
            }
            
            $ip = ip2long($ip);
            $subnet = ip2long($subnet);
            
            if ($ip === false || $subnet === false) {
                return false;
            }
            
            $mask = -1 << (32 - $bits);
            $subnet &= $mask;
            return ($ip & $mask) == $subnet;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 handling (simple version)
            return false; // Here you can extend IPv6 CIDR matching
        }
        
        return false;
    }

    /**
     * Content filter - Invisible detection of IP and automatically show/hide content
     * 
     * @param string $content Original content
     * @param Widget_Abstract_Contents $widget Content component
     * @return string Filtered content
     */
    public static function contentFilter($content, $widget)
    {
        $options = Typecho_Widget::widget('Widget_Options');
        $pluginOptions = $options->plugin('IPAuth');
        
        // If the plugin is not configured, return the original content
        if (!$pluginOptions) {
            return $content;
        }
        
        // Get user IP (including local and external)
        $ipInfo = self::getRealIP();
        $userIP = $ipInfo['local'];
        $externalIP = $ipInfo['external'];
        
        $authorizedIPs = array_filter(array_map('trim', explode("\n", $pluginOptions->authorizedIPs)));
        
        // Check if local IP and external IP are in the authorized list
        $isInList = self::isAuthorizedIP($userIP, $authorizedIPs);
        if (!$isInList && !empty($externalIP)) {
            $isInList = self::isAuthorizedIP($externalIP, $authorizedIPs);
        }
        
        // Decide whether to show content based on control mode
        $controlMode = isset($pluginOptions->controlMode) ? $pluginOptions->controlMode : 'whitelist';
        $shouldShowContent = ($controlMode === 'whitelist') ? $isInList : !$isInList;
        
        // Process protected content
        $pattern = '/\[ipauth\](.*?)\[\/ipauth\]/s';
        
        if ($shouldShowContent) {
            // Show protected content, removing tags
            $content = preg_replace($pattern, '$1', $content);
        } else {
            $logoUrl = self::sanitizeUrl(isset($pluginOptions->logoUrl) ? $pluginOptions->logoUrl : '');
            $customText = isset($pluginOptions->customText) ? htmlspecialchars($pluginOptions->customText, ENT_QUOTES, 'UTF-8') : '此区域的内容仅允许通过南方医科大学校内 IP 进行访问，请首先登入校园网环境。';
            $backgroundColor = self::sanitizeColor(isset($pluginOptions->backgroundColor) ? $pluginOptions->backgroundColor : '', '#f0f9ec');
            $themeColor = self::sanitizeColor(isset($pluginOptions->themeColor) ? $pluginOptions->themeColor : '', '#78C841');
            
            // Default Logo SVG (circular lock icon)
            $defaultLogo = '<svg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg">
                <circle cx="30" cy="30" r="28" fill="' . htmlspecialchars($themeColor, ENT_QUOTES, 'UTF-8') . '" opacity="0.1"/>
                <circle cx="30" cy="30" r="25" fill="none" stroke="' . htmlspecialchars($themeColor, ENT_QUOTES, 'UTF-8') . '" stroke-width="2"/>
                <path d="M30 15c-4.5 0-8 3.5-8 8v5h-2v12h20V28h-2v-5c0-4.5-3.5-8-8-8zm5 8v5H25v-5c0-2.8 2.2-5 5-5s5 2.2 5 5z" fill="' . htmlspecialchars($themeColor, ENT_QUOTES, 'UTF-8') . '"/>
            </svg>';
            
            $logoHTML = '';
            if (!empty($logoUrl)) {
                $logoHTML = '<img src="' . htmlspecialchars($logoUrl, ENT_QUOTES, 'UTF-8') . '" alt="Logo" style="width: 60px; height: 60px; margin-right: 20px; object-fit: contain;">';
            } else {
                $logoHTML = '<div style="margin-right: 20px;">' . $defaultLogo . '</div>';
            }
            
            $hiddenHTML = '
            <div style="
                background: ' . htmlspecialchars($backgroundColor, ENT_QUOTES, 'UTF-8') . ';
                border: 2px solid ' . htmlspecialchars($themeColor, ENT_QUOTES, 'UTF-8') . ';
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                display: flex;
                align-items: center;
                font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, \'Helvetica Neue\', Arial, sans-serif;
            ">
                ' . $logoHTML . '
                <div style="
                    color: ' . htmlspecialchars($themeColor, ENT_QUOTES, 'UTF-8') . ';
                    font-size: 16px;
                    line-height: 1.5;
                    flex: 1;
                ">' . $customText . '</div>
            </div>';
            
            $content = preg_replace($pattern, $hiddenHTML, $content);
        }
        
        // Debug mode display (admin only)
        if (isset($pluginOptions->debugMode) && $pluginOptions->debugMode && self::isAdmin()) {
            $debugInfo = '<div style="position: fixed; bottom: 10px; right: 10px; background: rgba(0,0,0,0.8); color: white; padding: 10px; border-radius: 5px; font-size: 12px; z-index: 9999; max-width: 300px;">';
            $debugInfo .= '内网IP: ' . htmlspecialchars($userIP, ENT_QUOTES, 'UTF-8');
            if (!empty($externalIP)) {
                $debugInfo .= '<br>外网IP: ' . htmlspecialchars($externalIP, ENT_QUOTES, 'UTF-8');
            }
            $debugInfo .= '<br>模式: ' . htmlspecialchars($controlMode, ENT_QUOTES, 'UTF-8') . ' | 状态: ' . ($shouldShowContent ? '可见' : '隐藏') . '</div>';
            $content .= $debugInfo;
        }
        
        return $content;
    }
    
    /**
     * Check if user is admin
     * 
     * @return bool
     */
    private static function isAdmin()
    {
        try {
            $user = Typecho_Widget::widget('Widget_User');
            return $user->hasLogin() && $user->pass('administrator', true);
        } catch (Exception $e) {
            return false;
        }
    }
}
