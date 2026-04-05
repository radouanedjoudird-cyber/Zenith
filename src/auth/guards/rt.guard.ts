import {
    ExecutionContext,
    Injectable,
    Logger,
    UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * REFRESH TOKEN GUARD (RtGuard):
 * Protects routes that require a valid refresh token.
 * Uses the 'jwt-refresh' Passport strategy (defined in rt.strategy.ts).
 * Unlike AtGuard, this guard extracts the raw token and attaches it
 * to req.user so the service can validate it against the stored hash.
 */
@Injectable()
export class RtGuard extends AuthGuard('jwt-refresh') {
  private readonly logger = new Logger(RtGuard.name);

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      const request = context.switchToHttp().getRequest();
      const ip = request.ip || request.headers['x-forwarded-for'];

      /**
       * AUDIT LOG:
       * Internal security log captures the IP and failure reason.
       * This data is critical for detecting token theft or replay attacks.
       */
      this.logger.error(
        `Refresh token validation failed from IP: ${ip} | Reason: ${info?.message || 'Invalid Token'}`,
      );

      /**
       * STEALTH MODE:
       * Generic error message prevents information leakage about
       * the internal token validation mechanism.
       */
      throw new UnauthorizedException('Access denied. Authentication required.');
    }

    return user;
  }
}