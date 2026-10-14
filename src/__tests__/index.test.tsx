import { Platform } from 'react-native';
import NativeModule from '../NativeRootJailDetect';

jest.mock('../NativeRootJailDetect', () => ({
  __esModule: true,
  default: {
    isDeviceCompromised: jest.fn(),
    isEmulator: jest.fn(),
    isSimulator: jest.fn(),
    isDebuggerAttached: jest.fn(),
    getDetectionReasons: jest.fn(),
    startSecurityWatchdog: jest.fn(),
    stopSecurityWatchdog: jest.fn(),
    isSecurityWatchdogRunning: jest.fn(),
    addListener: jest.fn(),
    removeListeners: jest.fn(),
  },
}));

import RootJailDetect, {
  ProtectionMode,
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
  startSecurityWatchdog,
  stopSecurityWatchdog,
  isSecurityWatchdogRunning,
  addSecurityThreatListener,
} from '../index';
import { DeviceEventEmitter } from 'react-native';

const mockNative = NativeModule as unknown as Record<
  string,
  jest.Mock | undefined
>;
const original = { ...mockNative } as Record<string, jest.Mock>;
const setOS = (os: 'android' | 'ios') => {
  Platform.OS = os;
};

let errorSpy: jest.SpyInstance;

beforeEach(() => {
  Object.keys(original).forEach((k) => {
    mockNative[k] = original[k];
    original[k]!.mockReset();
  });
  setOS('android');
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  errorSpy.mockRestore();
});

describe('ProtectionMode', () => {
  it('exposes the expected values', () => {
    expect(ProtectionMode.LOG_ONLY).toBe('LOG_ONLY');
    expect(ProtectionMode.THROW_EXCEPTION).toBe('THROW_EXCEPTION');
    expect(ProtectionMode.TERMINATE).toBe('TERMINATE');
  });
});

describe('default export', () => {
  it('exposes all public functions', () => {
    expect(RootJailDetect.isDeviceCompromised).toBe(isDeviceCompromised);
    expect(RootJailDetect.isEmulator).toBe(isEmulator);
    expect(RootJailDetect.isDebuggerAttached).toBe(isDebuggerAttached);
    expect(RootJailDetect.getDetectionReasons).toBe(getDetectionReasons);
    expect(RootJailDetect.startSecurityWatchdog).toBe(startSecurityWatchdog);
    expect(RootJailDetect.stopSecurityWatchdog).toBe(stopSecurityWatchdog);
    expect(RootJailDetect.isSecurityWatchdogRunning).toBe(
      isSecurityWatchdogRunning
    );
    expect(RootJailDetect.addSecurityThreatListener).toBe(
      addSecurityThreatListener
    );
  });
});

describe('isDeviceCompromised', () => {
  it('resolves true when native reports compromised', async () => {
    original.isDeviceCompromised!.mockResolvedValue(true);
    await expect(isDeviceCompromised()).resolves.toBe(true);
  });

  it('resolves false when native reports clean', async () => {
    original.isDeviceCompromised!.mockResolvedValue(false);
    await expect(isDeviceCompromised()).resolves.toBe(false);
  });

  it.each([
    [1, true],
    [0, false],
    [null, false],
    [undefined, false],
    ['yes', true],
    ['', false],
  ])('coerces %p to boolean %p', async (input, expected) => {
    original.isDeviceCompromised!.mockResolvedValue(input);
    await expect(isDeviceCompromised()).resolves.toBe(expected);
  });

  it('logs and rethrows native errors', async () => {
    const err = new Error('native failure');
    original.isDeviceCompromised!.mockRejectedValue(err);
    await expect(isDeviceCompromised()).rejects.toBe(err);
    expect(errorSpy).toHaveBeenCalledWith(
      'Error checking device security:',
      err
    );
  });

  it('rethrows synchronous native throws as rejections', async () => {
    original.isDeviceCompromised!.mockImplementation(() => {
      throw new Error('sync boom');
    });
    await expect(isDeviceCompromised()).rejects.toThrow('sync boom');
  });
});

describe('isEmulator', () => {
  it('uses isEmulator on Android', async () => {
    original.isEmulator!.mockResolvedValue(true);
    await expect(isEmulator()).resolves.toBe(true);
    expect(original.isEmulator).toHaveBeenCalledTimes(1);
    expect(original.isSimulator).not.toHaveBeenCalled();
  });

  it('returns false on Android for a real device', async () => {
    original.isEmulator!.mockResolvedValue(false);
    await expect(isEmulator()).resolves.toBe(false);
  });

  it('uses isSimulator on iOS', async () => {
    setOS('ios');
    original.isSimulator!.mockResolvedValue(true);
    await expect(isEmulator()).resolves.toBe(true);
    expect(original.isSimulator).toHaveBeenCalledTimes(1);
    expect(original.isEmulator).not.toHaveBeenCalled();
  });

  it('returns false on iOS for a real device', async () => {
    setOS('ios');
    original.isSimulator!.mockResolvedValue(false);
    await expect(isEmulator()).resolves.toBe(false);
  });

  it('returns false on Android when isEmulator is unavailable', async () => {
    mockNative.isEmulator = undefined;
    await expect(isEmulator()).resolves.toBe(false);
  });

  it('returns false on iOS when isSimulator is unavailable', async () => {
    setOS('ios');
    mockNative.isSimulator = undefined;
    await expect(isEmulator()).resolves.toBe(false);
  });

  it('returns false on unsupported platforms', async () => {
    (Platform as any).OS = 'web';
    await expect(isEmulator()).resolves.toBe(false);
    expect(original.isEmulator).not.toHaveBeenCalled();
    expect(original.isSimulator).not.toHaveBeenCalled();
  });

  it('swallows errors on Android and returns false', async () => {
    original.isEmulator!.mockRejectedValue(new Error('x'));
    await expect(isEmulator()).resolves.toBe(false);
    expect(errorSpy).toHaveBeenCalled();
  });

  it('swallows errors on iOS and returns false', async () => {
    setOS('ios');
    original.isSimulator!.mockRejectedValue(new Error('x'));
    await expect(isEmulator()).resolves.toBe(false);
    expect(errorSpy).toHaveBeenCalled();
  });
});

describe('isDebuggerAttached', () => {
  it('returns true when attached', async () => {
    original.isDebuggerAttached!.mockResolvedValue(true);
    await expect(isDebuggerAttached()).resolves.toBe(true);
  });

  it('returns false when not attached', async () => {
    original.isDebuggerAttached!.mockResolvedValue(false);
    await expect(isDebuggerAttached()).resolves.toBe(false);
  });

  it('coerces truthy/falsy values', async () => {
    original.isDebuggerAttached!.mockResolvedValue(1);
    await expect(isDebuggerAttached()).resolves.toBe(true);
    original.isDebuggerAttached!.mockResolvedValue(undefined);
    await expect(isDebuggerAttached()).resolves.toBe(false);
  });

  it('works on iOS too', async () => {
    setOS('ios');
    original.isDebuggerAttached!.mockResolvedValue(true);
    await expect(isDebuggerAttached()).resolves.toBe(true);
  });

  it('returns false when the native method is missing', async () => {
    mockNative.isDebuggerAttached = undefined;
    await expect(isDebuggerAttached()).resolves.toBe(false);
  });

  it('returns false and logs on error', async () => {
    original.isDebuggerAttached!.mockRejectedValue(new Error('x'));
    await expect(isDebuggerAttached()).resolves.toBe(false);
    expect(errorSpy).toHaveBeenCalledWith(
      'Error checking debugger status:',
      expect.any(Error)
    );
  });
});

describe('getDetectionReasons', () => {
  it('returns the reasons from native', async () => {
    original.getDetectionReasons!.mockResolvedValue(['su binary', 'magisk']);
    await expect(getDetectionReasons()).resolves.toEqual([
      'su binary',
      'magisk',
    ]);
  });

  it('returns an empty array when the device is clean', async () => {
    original.getDetectionReasons!.mockResolvedValue([]);
    await expect(getDetectionReasons()).resolves.toEqual([]);
  });

  it('returns an empty array when the native method is missing', async () => {
    mockNative.getDetectionReasons = undefined;
    await expect(getDetectionReasons()).resolves.toEqual([]);
  });

  it('returns an empty array and logs on error', async () => {
    original.getDetectionReasons!.mockRejectedValue(new Error('x'));
    await expect(getDetectionReasons()).resolves.toEqual([]);
    expect(errorSpy).toHaveBeenCalled();
  });
});

describe('startSecurityWatchdog', () => {
  it('applies defaults when called with no options', () => {
    startSecurityWatchdog();
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 3000,
      protectionMode: 'LOG_ONLY',
    });
  });

  it('applies defaults for an empty options object', () => {
    startSecurityWatchdog({});
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 3000,
      protectionMode: 'LOG_ONLY',
    });
  });

  it('passes custom interval and mode', () => {
    startSecurityWatchdog({
      interval: 5000,
      protectionMode: ProtectionMode.TERMINATE,
    });
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 5000,
      protectionMode: 'TERMINATE',
    });
  });

  it('supports THROW_EXCEPTION mode', () => {
    startSecurityWatchdog({ protectionMode: ProtectionMode.THROW_EXCEPTION });
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 3000,
      protectionMode: 'THROW_EXCEPTION',
    });
  });

  it('keeps a custom interval while defaulting the mode', () => {
    startSecurityWatchdog({ interval: 100 });
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 100,
      protectionMode: 'LOG_ONLY',
    });
  });

  it('respects an interval of 0 (nullish coalescing, not ||)', () => {
    startSecurityWatchdog({ interval: 0 });
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 0,
      protectionMode: 'LOG_ONLY',
    });
  });

  it('treats explicit undefined values as defaults', () => {
    startSecurityWatchdog({ interval: undefined, protectionMode: undefined });
    expect(original.startSecurityWatchdog).toHaveBeenCalledWith({
      interval: 3000,
      protectionMode: 'LOG_ONLY',
    });
  });

  it('propagates synchronous native errors', () => {
    original.startSecurityWatchdog!.mockImplementation(() => {
      throw new Error('start failed');
    });
    expect(() => startSecurityWatchdog()).toThrow('start failed');
  });
});

describe('stopSecurityWatchdog', () => {
  it('calls native stop once', () => {
    stopSecurityWatchdog();
    expect(original.stopSecurityWatchdog).toHaveBeenCalledTimes(1);
  });

  it('is safe to call repeatedly', () => {
    stopSecurityWatchdog();
    stopSecurityWatchdog();
    expect(original.stopSecurityWatchdog).toHaveBeenCalledTimes(2);
  });

  it('propagates synchronous native errors', () => {
    original.stopSecurityWatchdog!.mockImplementation(() => {
      throw new Error('stop failed');
    });
    expect(() => stopSecurityWatchdog()).toThrow('stop failed');
  });
});

describe('isSecurityWatchdogRunning', () => {
  it('returns true when running', async () => {
    original.isSecurityWatchdogRunning!.mockResolvedValue(true);
    await expect(isSecurityWatchdogRunning()).resolves.toBe(true);
  });

  it('returns false when stopped', async () => {
    original.isSecurityWatchdogRunning!.mockResolvedValue(false);
    await expect(isSecurityWatchdogRunning()).resolves.toBe(false);
  });

  it('returns false when the native method is missing', async () => {
    mockNative.isSecurityWatchdogRunning = undefined;
    await expect(isSecurityWatchdogRunning()).resolves.toBe(false);
  });

  it('returns false and logs on error', async () => {
    original.isSecurityWatchdogRunning!.mockRejectedValue(new Error('x'));
    await expect(isSecurityWatchdogRunning()).resolves.toBe(false);
    expect(errorSpy).toHaveBeenCalled();
  });
});

describe('addSecurityThreatListener', () => {
  const event = { reasons: ['Frida detected'], timestamp: 1 };

  it('delivers threat events to the listener', () => {
    const listener = jest.fn();
    const sub = addSecurityThreatListener(listener);
    DeviceEventEmitter.emit('onSecurityThreat', event);
    expect(listener).toHaveBeenCalledWith(event);
    sub.remove();
  });

  it('stops delivering after remove()', () => {
    const listener = jest.fn();
    const sub = addSecurityThreatListener(listener);
    sub.remove();
    DeviceEventEmitter.emit('onSecurityThreat', event);
    expect(listener).not.toHaveBeenCalled();
  });

  it('supports multiple independent listeners', () => {
    const a = jest.fn();
    const b = jest.fn();
    const subA = addSecurityThreatListener(a);
    const subB = addSecurityThreatListener(b);
    subA.remove();
    DeviceEventEmitter.emit('onSecurityThreat', event);
    expect(a).not.toHaveBeenCalled();
    expect(b).toHaveBeenCalledWith(event);
    subB.remove();
  });

  it('ignores other events', () => {
    const listener = jest.fn();
    const sub = addSecurityThreatListener(listener);
    DeviceEventEmitter.emit('somethingElse', event);
    expect(listener).not.toHaveBeenCalled();
    sub.remove();
  });

  it('rejects a non-function listener', () => {
    expect(() => addSecurityThreatListener(undefined as any)).toThrow(
      TypeError
    );
  });
});
