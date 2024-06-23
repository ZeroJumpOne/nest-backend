import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
  ) {}

  async canActivate(  context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if(!token) {
      throw new UnauthorizedException('No hay token para autorizar datos.');
    }

    
    // console.log({token});
    try {

      const payload = await this.jwtService.verifyAsync<JWTPayload>( token, { secret: process.env.JWT_SEED });
      // console.log({ payload});

      const user = await this.authService.findUserById( payload.id );
      if (!user) throw new UnauthorizedException('User does not exist');
      if (!user.isActive) throw new UnauthorizedException('User does not active');

      request['user']= user;
      // request['JWT']= token;

    } catch (error) {
      // console.log(error);      
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
