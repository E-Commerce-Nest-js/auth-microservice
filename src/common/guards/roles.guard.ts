import { CanActivate, ExecutionContext, mixin, Type } from '@nestjs/common';
import { Roles } from '../../auth/user.model';
import { AccessTokenPayloadDto } from '../dto/at-payload.dto';
import { JwtAccessAuthGuard } from './jwt-access.guard';

export const RolesGuard = (roles: Roles[]): Type<CanActivate> => {
    class RoleGuardMixin extends JwtAccessAuthGuard {
        async canActivate(context: ExecutionContext): Promise<boolean> {
            await super.canActivate(context);

            const request = context
                .switchToHttp()
                .getRequest<Request & { user: AccessTokenPayloadDto }>();
            const user = request.user;

            return roles.includes(user.role as Roles);
        }
    }

    return mixin(RoleGuardMixin);
};
