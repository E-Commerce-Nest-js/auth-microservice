import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions } from '@nestjs/jwt';
import { getPrivateKey } from './keys/keys.config';

export const getJwtConfig = async (configService: ConfigService): Promise<JwtModuleOptions> => {
    return {
        privateKey: getPrivateKey(),
        signOptions: {
            expiresIn: configService.get('JWT_ACCESS_EXPIRATION_TIME'),
            algorithm: 'RS256',
        },
    };
};
