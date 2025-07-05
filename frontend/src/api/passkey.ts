import { 
    startRegistration, 
    startAuthentication,
    type PublicKeyCredentialCreationOptionsJSON,
    type PublicKeyCredentialRequestOptionsJSON,
    type RegistrationResponseJSON,
    type AuthenticationResponseJSON,
    type AuthenticatorTransport
} from '@simplewebauthn/browser';
import { api } from './api';

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

    // 获取凭证列表
    async getCredentials(): Promise<PasskeyResponse<Authenticator[]>> {
        const response = await fetch(`${this.baseUrl}/credentials`, {
            credentials: 'include'
        });
        return response.json();
    }

    // 开始注册
    async startRegistration(credentialName: string): Promise<RegistrationOptions> {
        const response = await fetch(`${this.baseUrl}/register/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ credentialName })
        });
        return response.json();
    }

    // 完成注册
    async finishRegistration(
        credentialName: string, 
        response: RegistrationResponseJSON
    ): Promise<PasskeyResponse<{ verified: boolean }>> {
        const res = await fetch(`${this.baseUrl}/register/finish`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                credentialName,
                response
            })
        });
        return res.json();
    }

    // 开始认证
    async startAuthentication(username: string): Promise<AuthenticationOptions> {
        const response = await fetch(`${this.baseUrl}/authenticate/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ username })
        });
        return response.json();
    }

    // 完成认证
    async finishAuthentication(
        username: string,
        response: AuthenticationResponseJSON
    ): Promise<AuthResponse> {
        const res = await fetch(`${this.baseUrl}/authenticate/finish`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                username,
                response
            })
        });
        return res.json();
    }

    // 删除凭证
    async removeCredential(credentialId: string): Promise<PasskeyResponse<{ success: boolean }>> {
        const response = await fetch(`${this.baseUrl}/credentials/${credentialId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        return response.json();
    }
}

export const passkeyApi = new PasskeyApi();