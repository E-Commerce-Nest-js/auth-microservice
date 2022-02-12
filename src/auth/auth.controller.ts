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
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { TokenResponseDto } from './dto/token-response.dto';
import { UserResponseDto } from './dto/user-response.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @ApiOperation({ summary: 'Sign Up' })
    @ApiResponse({ status: 400, description: 'Return validation error' })
    @ApiResponse({ status: 422, description: 'User already exists' })
    @ApiResponse({ status: 201, description: 'Return created user', type: UserResponseDto })
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

    @ApiOperation({ summary: 'Sign In' })
    @ApiResponse({ status: 400, description: 'Return validation error' })
    @ApiResponse({ status: 401, description: 'Wrong login or password' })
    @ApiResponse({
        status: 200,
        description: 'Return Access-Token in the body and Refresh-Token in the cookie',
        headers: {
            'Set-Cookie': {
                description: '"Refresh=${token}; HttpOnly; Path=/; Max-Age=${expirationTime}"',
            },
        },
        type: TokenResponseDto,
    })
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

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Sign Out',
        description: 'This can only be done by the logged.',
    })
    @ApiResponse({ status: 401, description: 'Invalid Access-Token' })
    @ApiResponse({ status: 200, description: 'Clean Refresh-Token in cookie' })
    @UseGuards(JwtAccessAuthGuard)
    @Post('sign-out')
    @HttpCode(200)
    async signOut(@Req() req: RequestWithUser<AccessTokenPayloadDto>) {
        this.authService.removeRefreshToken(req.user.id);
        const cookie = this.authService.getCleanCookieForRefreshToken();
        req.res.setHeader('Set-Cookie', cookie);
        req.res.end();
    }

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Refresh tokens',
        description:
            'This can only be done by the logged. Refresh tokens when access token expires.',
    })
    @ApiResponse({ status: 401, description: 'Invalid Refresh-Token in cookie' })
    @ApiResponse({
        status: 200,
        description: 'Return Access-Token in the body and Refresh-Token in the cookie',
        headers: {
            'Set-Cookie': {
                description: '"Refresh=${token}; HttpOnly; Path=/; Max-Age=${expirationTime}"',
            },
        },
        type: TokenResponseDto,
    })
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

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get own data',
        description: 'This can only be done by the logged.',
    })
    @ApiResponse({ status: 401, description: 'Invalid Access-Token' })
    @ApiResponse({ status: 200, description: 'Return own data', type: UserResponseDto })
    @UseGuards(JwtAccessAuthGuard)
    @Get('iam')
    async getUser(@Req() req: RequestWithUser<AccessTokenPayloadDto>): Promise<UserResponseDto> {
        const user = await this.authService.getUserById(req.user.id);
        // _doc has user data from mongo
        return { ...user['_doc'], passwordHash: undefined, refresh_token: undefined };
    }

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Get array of users data',
        description: 'This can only be done by the logged in admin or manager.',
    })
    @ApiResponse({ status: 401, description: 'Invalid Access-Token' })
    @ApiResponse({ status: 403, description: 'Route for specific roles [admin, manager]' })
    @ApiResponse({
        status: 200,
        description: 'Return array of users',
        type: UserResponseDto,
        isArray: true,
    })
    @UseGuards(RolesGuard([Roles.Admin, Roles.Manager]))
    @Get('/users')
    async getUsersList() {
        return await this.authService.getUsersList();
    }

    @ApiBearerAuth()
    @ApiOperation({
        summary: 'Change role of user',
        description: 'This can only be done by the logged in admin.',
    })
    @ApiResponse({ status: 400, description: 'Return validation error' })
    @ApiResponse({ status: 401, description: 'Invalid Access-Token' })
    @ApiResponse({ status: 403, description: 'Route for specific roles [admin, manager]' })
    @ApiResponse({
        status: 200,
        description: 'Return user data with changed role',
        type: UserResponseDto,
    })
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
