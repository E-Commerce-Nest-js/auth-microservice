import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { getPublicKey } from '../../configs/keys/keys.config';
import { AccessTokenPayloadDto } from '../../common/dto/at-payload.dto';

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(Strategy, 'jwt-access') {
    constructor(private readonly configService: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: getPublicKey(),
            algorithms: ['RS256'],
        });
    }

    async validate(payload: AccessTokenPayloadDto): Promise<AccessTokenPayloadDto> {
        return payload;
    }
}
