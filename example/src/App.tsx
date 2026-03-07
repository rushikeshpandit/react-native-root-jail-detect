import { useState, useEffect } from 'react';
import {
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  Alert,
  ActivityIndicator,
  TouchableOpacity,
} from 'react-native';
import {
  isDeviceCompromised,
  isEmulator,
  isDebuggerAttached,
  getDetectionReasons,
} from 'react-native-root-jail-detect';
import { SafeAreaView } from 'react-native-safe-area-context';

function App() {
  const [loading, setLoading] = useState(true);
  const [isCompromised, setIsCompromised] = useState<boolean | null>(null);
  const [isEmu, setIsEmu] = useState<boolean | null>(null);
  const [isDebugger, setIsDebugger] = useState<boolean | null>(null);
  const [detectionReasons, setDetectionReasons] = useState<string[]>([]);

  const checkDeviceSecurity = async () => {
    setLoading(true);
    try {
      const [compromised, emulator, debuggerAttached, detectionReason]: [
        boolean,
        boolean,
        boolean,
        string[]
      ] = await Promise.all([
        isDeviceCompromised(),
        isEmulator(),
        isDebuggerAttached(),
        getDetectionReasons(),
      ]);

      setIsCompromised(compromised);
      setIsEmu(emulator);
      setIsDebugger(debuggerAttached);
      setDetectionReasons(detectionReason);

      if (compromised) {
        Alert.alert(
          'Security Warning',
          'This device appears to be rooted/jailbroken. Some features may be disabled for security reasons.',
          [{ text: 'OK' }]
        );
      }
    } catch (error) {
      console.error('Security check failed:', error);
      Alert.alert('Error', 'Failed to perform security check');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkDeviceSecurity();
  }, []);

  const getStatusColor = (value: boolean | null) => {
    if (value === null) return '#999';
    return value ? '#ff4444' : '#00C851';
  };

  const getStatusText = (value: boolean | null) => {
    if (value === null) return 'Checking...';
    return value ? 'YES' : 'NO';
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <ScrollView contentInsetAdjustmentBehavior="automatic">
        <View style={styles.header}>
          <Text style={styles.title}>Device Security Check</Text>
          <Text style={styles.subtitle}>
            Comprehensive security analysis of your device
          </Text>
        </View>

        {loading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#007AFF" />
            <Text style={styles.loadingText}>Analyzing device security...</Text>
          </View>
        ) : (
          <View style={styles.resultsContainer}>
            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Device Compromised</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isCompromised) },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {getStatusText(isCompromised)}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Checks if device is rooted (Android) or jailbroken (iOS)
              </Text>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Emulator/Simulator</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isEmu) },
                  ]}
                >
                  <Text style={styles.statusText}>{getStatusText(isEmu)}</Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Detects if app is running in emulator or simulator
              </Text>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Debugger Attached</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isDebugger) },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {getStatusText(isDebugger)}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Checks if debugger is currently attached
              </Text>
            </View>

            <TouchableOpacity
              style={styles.recheckButton}
              onPress={checkDeviceSecurity}
            >
              <Text style={styles.recheckButtonText}>Recheck Security</Text>
            </TouchableOpacity>

            {detectionReasons && detectionReasons.length > 0 && (
              <View style={styles.warningBox}>
                <Text style={styles.warningTitle}>Security Notice</Text>
                {detectionReasons.map((reason, index) => (
                  <Text key={index} style={styles.warningText}>
                    - {reason}
                  </Text>
                ))}
              </View>
            )}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    padding: 20,
    backgroundColor: '#fff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
  },
  loadingContainer: {
    padding: 40,
    alignItems: 'center',
  },
  loadingText: {
    marginTop: 16,
    fontSize: 16,
    color: '#666',
  },
  resultsContainer: {
    padding: 16,
  },
  resultCard: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  resultLabel: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333',
  },
  statusBadge: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 16,
  },
  statusText: {
    color: '#fff',
    fontWeight: 'bold',
    fontSize: 12,
  },
  resultDescription: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
  recheckButton: {
    backgroundColor: '#007AFF',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 8,
    marginBottom: 16,
  },
  recheckButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  warningBox: {
    backgroundColor: '#fff3cd',
    borderLeftWidth: 4,
    borderLeftColor: '#ff9800',
    padding: 16,
    borderRadius: 8,
  },
  warningTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#856404',
    marginBottom: 8,
  },
  warningText: {
    fontSize: 14,
    color: '#856404',
    lineHeight: 20,
  },
});

export default App;
