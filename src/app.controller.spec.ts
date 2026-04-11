import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { AppService } from './app.service';

/**
 * ZENITH CORE UNIT TESTS - APP LAYER
 * ------------------------------------------------------------------
 * @author Radouane Djoudi
 * @project Zenith Secure Engine
 * * * TEST STRATEGY:
 * 1. COMPONENT_ISOLATION: Verifies AppController in a sandboxed TestingModule.
 * 2. CONTRACT_VALIDATION: Ensures the API response matches the Zenith schema.
 * 3. LOGIC_INTEGRITY: Validates that AppService hydration flows correctly to the controller.
 */
describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('root', () => {
    /**
     * TEST: IDENTITY_EXPOSURE_CHECK
     * Ensures the root endpoint returns the correct operational status object.
     */
    it('should return the Zenith operational status object', () => {
      const result = appController.getHello();
      
      // 1. Structural Integrity Check
      expect(result).toHaveProperty('status', 'active');
      
      // 2. Content Consistency Check
      expect(result.message).toContain('Zenith Secure API is operational');
      
      // 3. Metadata Check
      expect(result).toHaveProperty('timestamp');
    });
  });
});