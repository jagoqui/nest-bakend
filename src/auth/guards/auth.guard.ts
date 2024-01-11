import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { JwtPayload } from '../interfaces/jwt-payload.model';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtSvc: JwtService, private authSvc: AuthService){

  }

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean>{
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    try {
      const payload = await this.jwtSvc.verifyAsync<JwtPayload>(
        token,
        {
          secret: process.env.JWT_SEED
        }
      );

      const user = await this.authSvc.findById(payload.id);
      if(!user){
        throw new UnauthorizedException('User does not exist');
      }
      if(!user.isActive){
        throw new UnauthorizedException('User is not active');
      }
      request['user'] = user;
    } catch {
      throw new UnauthorizedException();
    }
    return true
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
