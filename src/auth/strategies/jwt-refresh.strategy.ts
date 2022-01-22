import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { RefreshTokenPayloadDto } from '../../common/dto/rt-payload.dto';
import { getPublicKey } from '../../configs/keys/keys.config';
import { AuthService } from '../auth.service';
import { UserModel } from '../user.model';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
    constructor(
        private readonly configService: ConfigService,
        private readonly authService: AuthService,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (request: Request): string => {
                    return request?.cookies?.Refresh;
                },
            ]),
            passReqToCallback: true,
            secretOrKey: getPublicKey(),
            algorithms: ['RS256'],
        });
    }

    async validate(request: Request, payload: RefreshTokenPayloadDto): Promise<UserModel> {
        const refreshToken = request.cookies?.Refresh;
        return await this.authService.getUserIfRefreshTokenMatches(refreshToken, payload.id);
    }
}
