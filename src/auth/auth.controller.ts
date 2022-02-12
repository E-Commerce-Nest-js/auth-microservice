/* eslint-disable @typescript-eslint/explicit-function-return-type */
import {
    Body,
    Controller,
    Get,
    HttpCode,
    NotFoundException,
    Param,
    Patch,
    Post,
    Put,
    Req,
    UnauthorizedException,
    UnprocessableEntityException,
    UseGuards,
    UsePipes,
    ValidationPipe,
} from '@nestjs/common';
import { Request } from 'express';
import { AccessTokenPayloadDto } from '../common/dto/at-payload.dto';
import { JwtAccessAuthGuard } from '../common/guards/jwt-access.guard';
import { JwtRefreshAuthGuard } from '../common/guards/jwt-refresh.guard';
import { RolesGuard } from '../common/guards/roles.guard';
import { RequestWithUser } from '../common/types/request-with-user.type';
import {
    UNAUTHORIZED_ERROR,
    USER_ALREADY_EXISTS_ERROR,
    USER_NOT_FOUND_ERROR,
} from './auth.constants';
import { AuthService } from './auth.service';
import { SetRoleDto } from './dto/set-role.dto';
import { SignInDto } from './dto/signin.dto';
import { SignUpDto } from './dto/signup.dto';
import { UserModel } from './user.model';
import { Roles } from '../common/types/roles.type';
import { TokenResponseDto } from './dto/token-response.dto';
import { UserResponseDto } from './dto/user-response.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UsePipes(new ValidationPipe())
    @Post('sign-up')
    async signUp(@Body() dto: SignUpDto): Promise<UserResponseDto> {
        const oldUser = await this.authService.getUserByEmail(dto.email);
        if (oldUser) {
            throw new UnprocessableEntityException(USER_ALREADY_EXISTS_ERROR);
        }
        const user = await this.authService.createUser(dto);
        // _doc has user data from mongo
        return { ...user['_doc'], passwordHash: undefined };
    }

    @UsePipes(new ValidationPipe())
    @HttpCode(200)
    @Post('sign-in')
    async signIn(@Req() req: Request, @Body() dto: SignInDto): Promise<TokenResponseDto> {
        const user = await this.authService.validateUser(dto.email, dto.password);
        if (!user) {
            throw new UnauthorizedException(UNAUTHORIZED_ERROR);
        }
        const userId = user._id.toString();
        const refresh = await this.authService.getCookieWithRefreshToken(userId);
        await this.authService.setCurrentRefreshToken(refresh.token, userId);
        req.res.setHeader('Set-Cookie', refresh.cookie);
        const access_token = await this.authService.getAccessToken(user);
        return { access_token };
    }

    @UseGuards(JwtAccessAuthGuard)
    @Post('sign-out')
    @HttpCode(200)
    async signOut(@Req() req: RequestWithUser<AccessTokenPayloadDto>) {
        this.authService.removeRefreshToken(req.user.id);
        const cookie = this.authService.getCleanCookieForRefreshToken();
        req.res.setHeader('Set-Cookie', cookie);
        req.res.end();
    }

    @UseGuards(JwtRefreshAuthGuard)
    @Post('refresh')
    async refreshTokens(@Req() req: RequestWithUser<UserModel>): Promise<TokenResponseDto> {
        const user = await this.authService.getUserById(req.user.id);
        if (!user) {
            throw new UnauthorizedException(UNAUTHORIZED_ERROR);
        }
        const userId = user._id.toString();
        const refresh = await this.authService.getCookieWithRefreshToken(userId);
        await this.authService.setCurrentRefreshToken(refresh.token, userId);
        req.res.setHeader('Set-Cookie', refresh.cookie);
        const access_token = await this.authService.getAccessToken(user);
        return { access_token };
    }

    @UseGuards(JwtAccessAuthGuard)
    @Get('iam')
    async getUser(@Req() req: RequestWithUser<AccessTokenPayloadDto>): Promise<UserResponseDto> {
        const user = await this.authService.getUserById(req.user.id);
        // _doc has user data from mongo
        return { ...user['_doc'], passwordHash: undefined, refresh_token: undefined };
    }

    @UseGuards(RolesGuard([Roles.Admin, Roles.Manager]))
    @Get('/users')
    async getUsersList() {
        return await this.authService.getUsersList();
    }

    @UseGuards(RolesGuard([Roles.Admin]))
    @Patch('role')
    async setRole(@Body() dto: SetRoleDto): Promise<UserResponseDto> {
        const user = await this.authService.setRole(dto.userId, dto.role);
        if (!user) {
            throw new NotFoundException(USER_NOT_FOUND_ERROR);
        }
        return { ...user['_doc'], passwordHash: undefined, refresh_token: undefined };
    }
}
