#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OAuth Service - OAuth 业务逻辑层
处理第三方 OAuth 登录逻辑
"""
import logging
import requests
from typing import Dict, Optional

from application import settings
from core.oauth.base_oauth_service import BaseOAuthService

logger = logging.getLogger(__name__)


class GiteeOAuthService(BaseOAuthService):
    """Gitee OAuth 服务类"""
    
    PROVIDER_NAME = 'gitee'
    AUTHORIZE_URL = "https://gitee.com/oauth/authorize"
    TOKEN_URL = "https://gitee.com/oauth/token"
    USER_INFO_URL = "https://gitee.com/api/v5/user"
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取 Gitee 客户端配置"""
        return {
            'client_id': settings.GITEE_CLIENT_ID,
            'client_secret': settings.GITEE_CLIENT_SECRET,
            'redirect_uri': settings.GITEE_REDIRECT_URI,
        }
    
    @classmethod
    def get_user_info(cls, access_token: str) -> Optional[Dict]:
        """
        使用访问令牌获取 Gitee 用户信息
        
        Args:
            access_token: 访问令牌
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            params = {'access_token': access_token}
            response = requests.get(
                cls.USER_INFO_URL,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            if 'id' not in user_info:
                logger.error(f"Gitee 用户信息格式错误: {user_info}")
                return None
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求 Gitee 用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 Gitee 用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化 Gitee 用户信息
        
        Args:
            raw_user_info: Gitee 原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        return {
            'provider_id': str(raw_user_info.get('id')),
            'username': raw_user_info.get('login'),
            'name': raw_user_info.get('name', raw_user_info.get('login')),
            'email': raw_user_info.get('email'),
            'avatar': raw_user_info.get('avatar_url'),
            'bio': raw_user_info.get('bio'),
        }


class GitHubOAuthService(BaseOAuthService):
    """GitHub OAuth 服务类"""
    
    PROVIDER_NAME = 'github'
    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_INFO_URL = "https://api.github.com/user"
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取 GitHub 客户端配置"""
        return {
            'client_id': settings.GITHUB_CLIENT_ID,
            'client_secret': settings.GITHUB_CLIENT_SECRET,
            'redirect_uri': settings.GITHUB_REDIRECT_URI,
        }
    
    @classmethod
    def get_extra_authorize_params(cls) -> Dict[str, str]:
        """GitHub 需要 scope 参数"""
        return {
            'scope': 'user:email',  # 请求用户邮箱权限
        }
    
    @classmethod
    def get_token_request_headers(cls) -> Dict[str, str]:
        """GitHub 需要 Accept header 来获取 JSON 响应"""
        return {
            'Accept': 'application/json',
        }
    
    @classmethod
    def get_user_info(cls, access_token: str) -> Optional[Dict]:
        """
        使用访问令牌获取 GitHub 用户信息
        
        Args:
            access_token: 访问令牌
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
            }
            response = requests.get(
                cls.USER_INFO_URL,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            if 'id' not in user_info:
                logger.error(f"GitHub 用户信息格式错误: {user_info}")
                return None
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求 GitHub 用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 GitHub 用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化 GitHub 用户信息
        
        Args:
            raw_user_info: GitHub 原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        return {
            'provider_id': str(raw_user_info.get('id')),
            'username': raw_user_info.get('login'),
            'name': raw_user_info.get('name') or raw_user_info.get('login'),
            'email': raw_user_info.get('email'),
            'avatar': raw_user_info.get('avatar_url'),
            'bio': raw_user_info.get('bio'),
        }


class QQOAuthService(BaseOAuthService):
    """QQ 互联 OAuth 服务类"""
    
    PROVIDER_NAME = 'qq'
    AUTHORIZE_URL = "https://graph.qq.com/oauth2.0/authorize"
    TOKEN_URL = "https://graph.qq.com/oauth2.0/token"
    USER_INFO_URL = "https://graph.qq.com/user/get_user_info"
    OPENID_URL = "https://graph.qq.com/oauth2.0/me"
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取 QQ 客户端配置"""
        return {
            'client_id': settings.QQ_APP_ID,
            'client_secret': settings.QQ_APP_KEY,
            'redirect_uri': settings.QQ_REDIRECT_URI,
        }
    
    @classmethod
    def get_extra_authorize_params(cls) -> Dict[str, str]:
        """QQ 需要 response_type 参数"""
        return {
            'response_type': 'code',
        }
    
    @classmethod
    def get_access_token(cls, code: str) -> Optional[str]:
        """
        使用授权码获取访问令牌
        
        QQ 返回的是 URL 参数格式，需要特殊处理
        
        Args:
            code: 授权码
        
        Returns:
            Optional[str]: 访问令牌，失败返回 None
        """
        try:
            config = cls.get_client_config()
            
            params = {
                'grant_type': 'authorization_code',
                'client_id': config['client_id'],
                'client_secret': config['client_secret'],
                'code': code,
                'redirect_uri': config['redirect_uri'],
            }
            
            response = requests.get(
                cls.TOKEN_URL,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            # QQ 返回的是 URL 参数格式: access_token=xxx&expires_in=xxx
            response_text = response.text
            
            # 解析 access_token
            import re
            match = re.search(r'access_token=([^&]+)', response_text)
            if match:
                access_token = match.group(1)
                logger.info(f"QQ access_token 获取成功")
                return access_token
            else:
                logger.error(f"QQ access_token 解析失败: {response_text}")
                return None
                
        except requests.RequestException as e:
            logger.error(f"请求 QQ access_token 失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 QQ access_token 异常: {str(e)}")
            return None
    
    @classmethod
    def get_user_info(cls, access_token: str) -> Optional[Dict]:
        """
        使用访问令牌获取 QQ 用户信息
        
        QQ 需要先获取 openid，再获取用户信息
        
        Args:
            access_token: 访问令牌
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            # 1. 获取 openid
            openid_response = requests.get(
                cls.OPENID_URL,
                params={'access_token': access_token},
                timeout=10
            )
            openid_response.raise_for_status()
            
            # QQ 返回的是 JSONP 格式: callback( {"client_id":"xxx","openid":"xxx"} );
            openid_text = openid_response.text
            
            # 解析 openid
            import json
            import re
            match = re.search(r'callback\(\s*(\{.*?\})\s*\)', openid_text)
            if not match:
                logger.error(f"QQ openid 解析失败: {openid_text}")
                return None
            
            openid_data = json.loads(match.group(1))
            openid = openid_data.get('openid')
            
            if not openid:
                logger.error(f"QQ openid 不存在: {openid_data}")
                return None
            
            logger.info(f"QQ openid 获取成功: {openid}")
            
            # 2. 获取用户信息
            config = cls.get_client_config()
            user_response = requests.get(
                cls.USER_INFO_URL,
                params={
                    'access_token': access_token,
                    'oauth_consumer_key': config['client_id'],
                    'openid': openid
                },
                timeout=10
            )
            user_response.raise_for_status()
            
            user_info = user_response.json()
            
            # 检查返回状态
            if user_info.get('ret') != 0:
                logger.error(f"QQ 用户信息获取失败: {user_info.get('msg')}")
                return None
            
            # 将 openid 添加到用户信息中
            user_info['openid'] = openid
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求 QQ 用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 QQ 用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化 QQ 用户信息
        
        Args:
            raw_user_info: QQ 原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        return {
            'provider_id': raw_user_info.get('openid'),
            'username': raw_user_info.get('nickname', '').replace(' ', '_'),  # QQ 昵称可能有空格
            'name': raw_user_info.get('nickname'),
            'email': None,  # QQ 不提供邮箱
            'avatar': raw_user_info.get('figureurl_qq_2') or raw_user_info.get('figureurl_qq_1'),
            'bio': None,
        }


class GoogleOAuthService(BaseOAuthService):
    """Google OAuth 服务类"""
    
    PROVIDER_NAME = 'google'
    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取 Google 客户端配置"""
        return {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
        }
    
    @classmethod
    def get_extra_authorize_params(cls) -> Dict[str, str]:
        """Google 需要 scope 和 access_type 参数"""
        return {
            'scope': 'openid email profile',
            'access_type': 'offline',
            'response_type': 'code',
        }
    
    @classmethod
    def get_user_info(cls, access_token: str) -> Optional[Dict]:
        """
        使用访问令牌获取 Google 用户信息
        
        Args:
            access_token: 访问令牌
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
            }
            response = requests.get(
                cls.USER_INFO_URL,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            if 'id' not in user_info:
                logger.error(f"Google 用户信息格式错误: {user_info}")
                return None
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求 Google 用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 Google 用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化 Google 用户信息
        
        Args:
            raw_user_info: Google 原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        return {
            'provider_id': raw_user_info.get('id'),
            'username': raw_user_info.get('email', '').split('@')[0],  # 使用邮箱前缀作为用户名
            'name': raw_user_info.get('name') or raw_user_info.get('email'),
            'email': raw_user_info.get('email'),
            'avatar': raw_user_info.get('picture'),
            'bio': None,
        }


class WeChatOAuthService(BaseOAuthService):
    """微信开放平台 OAuth 服务类"""
    
    PROVIDER_NAME = 'wechat'
    AUTHORIZE_URL = "https://open.weixin.qq.com/connect/qrconnect"
    TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"
    USER_INFO_URL = "https://api.weixin.qq.com/sns/userinfo"
    
    @classmethod
    def get_user_id_field(cls) -> str:
        """微信使用 unionid 作为唯一标识"""
        return 'wechat_unionid'
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取微信客户端配置"""
        return {
            'client_id': settings.WECHAT_APP_ID,
            'client_secret': settings.WECHAT_APP_SECRET,
            'redirect_uri': settings.WECHAT_REDIRECT_URI,
        }
    
    @classmethod
    def get_extra_authorize_params(cls) -> Dict[str, str]:
        """微信需要 appid 和 scope 参数"""
        config = cls.get_client_config()
        return {
            'appid': config['client_id'],  # 微信使用 appid 而不是 client_id
            'scope': 'snsapi_login',  # 网页扫码登录
            'response_type': 'code',
        }
    
    @classmethod
    def get_authorize_url(cls, state: Optional[str] = None) -> str:
        """
        获取微信授权 URL
        微信的参数名称与标准 OAuth 2.0 不同
        """
        config = cls.get_client_config()
        extra_params = cls.get_extra_authorize_params()
        
        params = {
            'appid': config['client_id'],
            'redirect_uri': config['redirect_uri'],
            'response_type': 'code',
            'scope': extra_params['scope'],
        }
        
        if state:
            params['state'] = state
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        # 微信需要添加 #wechat_redirect 锚点
        return f"{cls.AUTHORIZE_URL}?{query_string}#wechat_redirect"
    
    @classmethod
    def get_access_token(cls, code: str) -> Optional[Dict]:
        """
        使用授权码获取访问令牌
        微信的参数名称与标准 OAuth 2.0 不同
        
        Returns:
            Dict: 包含 access_token 和 openid
        """
        try:
            config = cls.get_client_config()
            params = {
                'appid': config['client_id'],      # 微信用 appid
                'secret': config['client_secret'],  # 微信用 secret
                'code': code,
                'grant_type': 'authorization_code',
            }
            
            response = requests.get(
                cls.TOKEN_URL,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            token_data = response.json()
            
            # 检查错误
            if 'errcode' in token_data:
                logger.error(f"微信获取 token 失败: {token_data}")
                return None
            
            if 'access_token' not in token_data or 'openid' not in token_data:
                logger.error(f"微信 token 响应格式错误: {token_data}")
                return None
            
            return token_data
            
        except requests.RequestException as e:
            logger.error(f"请求微信 token 失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取微信 token 异常: {str(e)}")
            return None
    
    @classmethod
    def get_user_info(cls, access_token: str, openid: str = None) -> Optional[Dict]:
        """
        使用访问令牌获取微信用户信息
        微信需要同时传递 access_token 和 openid
        
        Args:
            access_token: 访问令牌
            openid: 用户的 openid
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            params = {
                'access_token': access_token,
                'openid': openid,
                'lang': 'zh_CN',
            }
            
            response = requests.get(
                cls.USER_INFO_URL,
                params=params,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            # 检查错误
            if 'errcode' in user_info:
                logger.error(f"微信获取用户信息失败: {user_info}")
                return None
            
            if 'openid' not in user_info:
                logger.error(f"微信用户信息格式错误: {user_info}")
                return None
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求微信用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取微信用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化微信用户信息
        
        Args:
            raw_user_info: 微信原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        # 优先使用 unionid，如果没有则使用 openid
        provider_id = raw_user_info.get('unionid') or raw_user_info.get('openid')
        
        # 微信昵称可能包含 emoji 和特殊字符，需要处理
        nickname = raw_user_info.get('nickname', '')
        username = nickname.replace(' ', '_')[:30] if nickname else f"wechat_{provider_id[:8]}"
        
        return {
            'provider_id': provider_id,
            'username': username,
            'name': nickname or username,
            'email': None,  # 微信不提供邮箱
            'avatar': raw_user_info.get('headimgurl'),
            'bio': None,
        }
    
    @classmethod
    def handle_oauth_login(cls, code: str, state: Optional[str] = None) -> Optional[Dict]:
        """
        处理微信 OAuth 登录流程
        重写此方法以处理微信特殊的 token 响应
        """
        # 1. 获取 access_token 和 openid
        token_data = cls.get_access_token(code)
        if not token_data:
            return None
        
        access_token = token_data.get('access_token')
        openid = token_data.get('openid')
        
        if not access_token or not openid:
            logger.error("微信 token 数据缺少必要字段")
            return None
        
        # 2. 获取用户信息（需要传递 openid）
        raw_user_info = cls.get_user_info(access_token, openid)
        if not raw_user_info:
            return None
        
        # 3. 标准化用户信息
        user_info = cls.normalize_user_info(raw_user_info)
        
        # 4. 创建或更新用户
        user = cls.create_or_update_user(user_info)
        if not user:
            return None
        
        # 5. 生成 JWT token
        return cls.generate_tokens(user)


class MicrosoftOAuthService(BaseOAuthService):
    """微软 OAuth 服务类 (Microsoft Identity Platform)"""
    
    PROVIDER_NAME = 'microsoft'
    AUTHORIZE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    USER_INFO_URL = "https://graph.microsoft.com/v1.0/me"
    
    @classmethod
    def get_client_config(cls) -> Dict[str, str]:
        """获取微软客户端配置"""
        return {
            'client_id': settings.MICROSOFT_CLIENT_ID,
            'client_secret': settings.MICROSOFT_CLIENT_SECRET,
            'redirect_uri': settings.MICROSOFT_REDIRECT_URI,
        }
    
    @classmethod
    def get_extra_authorize_params(cls) -> Dict[str, str]:
        """微软需要 scope 和 response_mode 参数"""
        return {
            'scope': 'openid email profile User.Read',
            'response_type': 'code',
            'response_mode': 'query',
        }
    
    @classmethod
    def get_user_info(cls, access_token: str) -> Optional[Dict]:
        """
        使用 Microsoft Graph API 获取用户信息
        
        Args:
            access_token: 访问令牌
        
        Returns:
            Optional[Dict]: 用户信息字典，失败返回 None
        """
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
            }
            response = requests.get(
                cls.USER_INFO_URL,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            user_info = response.json()
            
            if 'id' not in user_info:
                logger.error(f"Microsoft 用户信息格式错误: {user_info}")
                return None
            
            return user_info
            
        except requests.RequestException as e:
            logger.error(f"请求 Microsoft 用户信息失败: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"获取 Microsoft 用户信息异常: {str(e)}")
            return None
    
    @classmethod
    def normalize_user_info(cls, raw_user_info: Dict) -> Dict:
        """
        标准化微软用户信息
        
        Args:
            raw_user_info: Microsoft 原始用户信息
        
        Returns:
            Dict: 标准化后的用户信息
        """
        # 使用 userPrincipalName 的前缀作为用户名
        user_principal_name = raw_user_info.get('userPrincipalName', '')
        username = user_principal_name.split('@')[0] if '@' in user_principal_name else user_principal_name
        
        # 优先使用 mail，如果没有则使用 userPrincipalName
        email = raw_user_info.get('mail') or raw_user_info.get('userPrincipalName')
        
        return {
            'provider_id': raw_user_info.get('id'),
            'username': username or f"ms_{raw_user_info.get('id', '')[:8]}",
            'name': raw_user_info.get('displayName') or username,
            'email': email,
            'avatar': None,  # Microsoft Graph 需要额外 API 调用获取头像
            'bio': raw_user_info.get('jobTitle'),
        }
