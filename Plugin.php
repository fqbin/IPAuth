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

        // Logo URL configuration
        $logoUrl = new Typecho_Widget_Helper_Form_Element_Text(
            'logoUrl',
            NULL,
            '',
            _t('提示框Logo URL'),
            _t('隐藏内容提示框的Logo图片URL，留空使用默认图标')
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

        // Detect external IP
        $detectExternalIP = new Typecho_Widget_Helper_Form_Element_Radio(
            'detectExternalIP',
            array('1' => _t('启用'), '0' => _t('禁用')),
            '1',
            _t('外网IP检测'),
            _t('启用后会同时检测外网IP地址')
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
     * Get user's real IP address
     * 
     * @return array Returns local IP and external IP
     */
    private static function getRealIP()
    {
        $localIP = '';
        $externalIP = '';
        
        // Get local IP
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $localIP = trim($ips[0]);
        } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $localIP = $_SERVER['HTTP_X_REAL_IP'];
        } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $localIP = $_SERVER['HTTP_CLIENT_IP'];
        } else {
            $localIP = $_SERVER['REMOTE_ADDR'];
        }
        
        // Try to get external IP (if enabled)
        $options = Typecho_Widget::widget('Widget_Options');
        $pluginOptions = $options->plugin('IPAuth');
        
        if ($pluginOptions && isset($pluginOptions->detectExternalIP) && $pluginOptions->detectExternalIP == '1') {
            // Method 1: Get from HTTP header (safest, no external requests)
            if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                // Cloudflare
                $externalIP = $_SERVER['HTTP_CF_CONNECTING_IP'];
            } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                // Get the last IP in the X-Forwarded-For chain (usually the original client IP)
                $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                $externalIP = trim(end($ips));
            } elseif (!empty($_SERVER['HTTP_TRUE_CLIENT_IP'])) {
                // Akamai and Cloudflare
                $externalIP = $_SERVER['HTTP_TRUE_CLIENT_IP'];
            } elseif (!empty($_SERVER['HTTP_X_CLUSTER_CLIENT_IP'])) {
                // Rackspace Cloud Load Balancer
                $externalIP = $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'];
            }
            
            // Method 2: Use multiple trusted services to verify (optional, reduces hijacking risk)
            if (empty($externalIP) || $externalIP === $localIP) {
                $externalIP = self::getExternalIPFromMultipleSources();
            }
            
            // Validate the gotten IP whether it's a valid public IP
            if (!empty($externalIP)) {
                // Filter private IP addresses
                if (self::isPrivateIP($externalIP)) {
                    $externalIP = '';
                }
            }
            
            // If the external IP and local IP are the same, consider no valid external IP has been obtained
            if ($externalIP === $localIP) {
                $externalIP = '';
            }
        }
        
        return array('local' => $localIP, 'external' => $externalIP);
    }
    
    /**
     * Get external IP from multiple trusted sources (increases security)
     * 
     * @return string
     */
    private static function getExternalIPFromMultipleSources()
    {
        // Use multiple trusted IP detection services
        $services = array(
            'https://ipv4.icanhazip.com',      // High credibility
            'https://api.ipify.org',            // High credibility
            'https://ipecho.net/plain',         // Backup
            'https://checkip.amazonaws.com',    // AWS official service
        );
        
        $context = stream_context_create([
            'http' => [
                'timeout' => 1,  // 1 second timeout
                'method' => 'GET',
                'header' => 'User-Agent: Typecho IPAuth Plugin',
                'follow_location' => 0,  // Do not follow redirects
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ]
        ]);
        
        $results = array();
        
        // Try to get the IP from multiple services
        foreach ($services as $service) {
            $response = @file_get_contents($service, false, $context);
            if ($response !== false) {
                $ip = trim($response);
                // Validate if it's a valid IPv4 address
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    $results[] = $ip;
                    // If two services return the same IP, consider it trusted
                    if (count(array_keys($results, $ip)) >= 2) {
                        return $ip;
                    }
                }
            }
        }
        
        // If there is only one result, return it (but lower credibility)
        if (!empty($results)) {
            return $results[0];
        }
        
        return '';
    }
    
    /**
     * Check if the IP address is private
     * 
     * @param string $ip
     * @return bool
     */
    private static function isPrivateIP($ip)
    {
        // Use PHP built-in filter to check if it's a private or reserved IP
        return !filter_var(
            $ip, 
            FILTER_VALIDATE_IP, 
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
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
        list($subnet, $bits) = explode('/', $range);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4
            $ip = ip2long($ip);
            $subnet = ip2long($subnet);
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
            // Generate custom styled hidden content prompt
            $logoUrl = isset($pluginOptions->logoUrl) ? $pluginOptions->logoUrl : '';
            $customText = isset($pluginOptions->customText) ? $pluginOptions->customText : '此区域的内容仅允许通过南方医科大学校内 IP 进行访问，请首先登入校园网环境。';
            $backgroundColor = isset($pluginOptions->backgroundColor) ? $pluginOptions->backgroundColor : '#f0f9ec';
            $themeColor = isset($pluginOptions->themeColor) ? $pluginOptions->themeColor : '#78C841';
            
            // Default Logo SVG (circular lock icon)
            $defaultLogo = '<svg width="60" height="60" viewBox="0 0 60 60" xmlns="http://www.w3.org/2000/svg">
                <circle cx="30" cy="30" r="28" fill="' . $themeColor . '" opacity="0.1"/>
                <circle cx="30" cy="30" r="25" fill="none" stroke="' . $themeColor . '" stroke-width="2"/>
                <path d="M30 15c-4.5 0-8 3.5-8 8v5h-2v12h20V28h-2v-5c0-4.5-3.5-8-8-8zm5 8v5H25v-5c0-2.8 2.2-5 5-5s5 2.2 5 5z" fill="' . $themeColor . '"/>
            </svg>';
            
            $logoHTML = '';
            if (!empty($logoUrl)) {
                $logoHTML = '<img src="' . $logoUrl . '" alt="Logo" style="width: 60px; height: 60px; margin-right: 20px;">';
            } else {
                $logoHTML = '<div style="margin-right: 20px;">' . $defaultLogo . '</div>';
            }
            
            $hiddenHTML = '
            <div style="
                background: ' . $backgroundColor . ';
                border: 2px solid ' . $themeColor . ';
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                display: flex;
                align-items: center;
                font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, \'Helvetica Neue\', Arial, sans-serif;
            ">
                ' . $logoHTML . '
                <div style="
                    color: ' . $themeColor . ';
                    font-size: 16px;
                    line-height: 1.5;
                    flex: 1;
                ">' . htmlspecialchars($customText) . '</div>
            </div>';
            
            $content = preg_replace($pattern, $hiddenHTML, $content);
        }
        
        // Debug mode: show current IP (only for admin)
        if (isset($pluginOptions->debugMode) && $pluginOptions->debugMode && self::isAdmin()) {
            $debugInfo = '<div style="position: fixed; bottom: 10px; right: 10px; background: rgba(0,0,0,0.8); color: white; padding: 10px; border-radius: 5px; font-size: 12px; z-index: 9999;">';
            $debugInfo .= '内网IP: ' . $userIP;
            if (!empty($externalIP)) {
                $debugInfo .= ' | 外网IP: ' . $externalIP;
            }
            $debugInfo .= ' | 模式: ' . $controlMode . ' | 状态: ' . ($shouldShowContent ? '可见' : '隐藏') . '</div>';
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
        $user = Typecho_Widget::widget('Widget_User');
        return $user->hasLogin() && $user->pass('administrator', true);
    }
}
