import { ExecutionContext, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(AtGuard.name);

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'];

      // AUDIT LOG: Internal log for security monitoring (IP + Reason)
      this.logger.error(`Unauthorized access attempt from IP: ${ip} | Reason: ${info?.message || 'Invalid Token'}`);

      // STEALTH MODE: Throw generic error to prevent "Information Leakage"
      throw new UnauthorizedException('Access denied. Authentication required.');
    }
    return user;
  }
}