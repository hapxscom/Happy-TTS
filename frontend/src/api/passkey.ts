import { 
    startRegistration, 
    startAuthentication,
    type PublicKeyCredentialCreationOptionsJSON,
    type PublicKeyCredentialRequestOptionsJSON,
    type RegistrationResponseJSON,
    type AuthenticationResponseJSON,
    type AuthenticatorTransport
} from '@simplewebauthn/browser';

export interface Authenticator {
    id: string;
    credentialID: string;
    name: string;
    transports?: AuthenticatorTransport[];
    deviceType?: 'singleDevice' | 'multiDevice';
    backedUp?: boolean;
}

interface PasskeyResponse<T> {
    data: T;
    success: boolean;
    error?: string;
}

interface AuthResponse extends PasskeyResponse<{
    token: string;
    user: {
        id: string;
        username: string;
    };
}> {}

interface RegistrationOptions extends PasskeyResponse<{
    options: PublicKeyCredentialCreationOptionsJSON;
}> {}

interface AuthenticationOptions extends PasskeyResponse<{
    options: PublicKeyCredentialRequestOptionsJSON;
}> {}

class PasskeyApi {
    private baseUrl = '/api/passkey';

    private async handleResponse<T>(response: Response): Promise<T> {
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error('Unauthorized');
            }
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                const error = await response.json();
                throw new Error(error.error || '请求失败');
            } else {
                throw new Error('服务器错误');
            }
        }
        return response.json();
    }

    private getHeaders(): HeadersInit {
        const token = localStorage.getItem('token');
        return {
            'Content-Type': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        };
    }

    // 获取凭证列表
    async getCredentials(): Promise<PasskeyResponse<Authenticator[]>> {
        const response = await fetch(`${this.baseUrl}/credentials`, {
            headers: this.getHeaders(),
            credentials: 'include'
        });
        return this.handleResponse(response);
    }

    // 开始注册
    async startRegistration(credentialName: string): Promise<RegistrationOptions> {
        const response = await fetch(`${this.baseUrl}/register/start`, {
            method: 'POST',
            headers: this.getHeaders(),
            credentials: 'include',
            body: JSON.stringify({ credentialName })
        });
        return this.handleResponse(response);
    }

    // 完成注册
    async finishRegistration(
        credentialName: string, 
        response: RegistrationResponseJSON
    ): Promise<PasskeyResponse<{ verified: boolean }>> {
        const res = await fetch(`${this.baseUrl}/register/finish`, {
            method: 'POST',
            headers: this.getHeaders(),
            credentials: 'include',
            body: JSON.stringify({
                credentialName,
                response
            })
        });
        return this.handleResponse(res);
    }

    // 开始认证
    async startAuthentication(username: string): Promise<AuthenticationOptions> {
        const response = await fetch(`${this.baseUrl}/authenticate/start`, {
            method: 'POST',
            headers: this.getHeaders(),
            credentials: 'include',
            body: JSON.stringify({ username })
        });
        return this.handleResponse(response);
    }

    // 完成认证
    async finishAuthentication(
        username: string,
        response: AuthenticationResponseJSON
    ): Promise<AuthResponse> {
        const res = await fetch(`${this.baseUrl}/authenticate/finish`, {
            method: 'POST',
            headers: this.getHeaders(),
            credentials: 'include',
            body: JSON.stringify({
                username,
                response
            })
        });
        return this.handleResponse(res);
    }

    // 删除凭证
    async removeCredential(credentialId: string): Promise<PasskeyResponse<{ success: boolean }>> {
        const response = await fetch(`${this.baseUrl}/credentials/${credentialId}`, {
            method: 'DELETE',
            headers: this.getHeaders(),
            credentials: 'include'
        });
        return this.handleResponse(response);
    }
}

export const passkeyApi = new PasskeyApi();