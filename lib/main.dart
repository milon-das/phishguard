import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:file_picker/file_picker.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'dart:io';
import 'dart:async';
import 'dart:ui' show FontFeature;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:intl/intl.dart';
import 'package:app_links/app_links.dart';

// History Item Model
class HistoryItem {
  final String id;
  final String type; // 'File', 'Hash', 'URL', 'QR'
  final String name; // file name, hash, or URL
  final String verdict; // 'Safe', 'Malicious', 'Unknown'
  final String detectionStats; // e.g., "5/75 vendors flagged"
  final DateTime timestamp;
  final DateTime cacheUntil; // Cache valid until (timestamp + 8 hours)
  final DateTime expiresAt; // Auto-delete after 7 days
  final Map<String, dynamic>? fullData; // Complete VT response for detail view

  HistoryItem({
    required this.id,
    required this.type,
    required this.name,
    required this.verdict,
    required this.detectionStats,
    required this.timestamp,
    DateTime? cacheUntil,
    DateTime? expiresAt,
    this.fullData,
  })  : cacheUntil = cacheUntil ?? timestamp.add(const Duration(hours: 8)),
        expiresAt = expiresAt ?? timestamp.add(const Duration(days: 7));

  // Check if cache is still valid
  bool get isCacheValid => DateTime.now().isBefore(cacheUntil);

  // Check if item should be deleted
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  // Get remaining days until deletion
  int get daysUntilDeletion {
    final remaining = expiresAt.difference(DateTime.now()).inDays;
    return remaining > 0 ? remaining : 0;
  }

  // Convert to JSON for storage
  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type,
        'name': name,
        'verdict': verdict,
        'detectionStats': detectionStats,
        'timestamp': timestamp.toIso8601String(),
        'cacheUntil': cacheUntil.toIso8601String(),
        'expiresAt': expiresAt.toIso8601String(),
        'fullData': fullData,
      };

  // Create from JSON
  factory HistoryItem.fromJson(Map<String, dynamic> json) => HistoryItem(
        id: json['id'] as String,
        type: json['type'] as String,
        name: json['name'] as String,
        verdict: json['verdict'] as String,
        detectionStats: json['detectionStats'] as String,
        timestamp: DateTime.parse(json['timestamp'] as String),
        cacheUntil: json['cacheUntil'] != null
            ? DateTime.parse(json['cacheUntil'] as String)
            : DateTime.parse(json['timestamp'] as String)
                .add(const Duration(hours: 8)),
        expiresAt: json['expiresAt'] != null
            ? DateTime.parse(json['expiresAt'] as String)
            : DateTime.parse(json['timestamp'] as String)
                .add(const Duration(days: 7)),
        fullData: json['fullData'] as Map<String, dynamic>?,
      );
}

// History Manager Class
class HistoryManager {
  static const String _historyKey = 'scan_history';

  // Save a history item
  static Future<void> saveHistoryItem(HistoryItem item) async {
    final prefs = await SharedPreferences.getInstance();
    List<String> historyJson = prefs.getStringList(_historyKey) ?? [];

    // Clean expired items (7+ days old) before saving
    historyJson = historyJson.where((jsonStr) {
      try {
        final Map<String, dynamic> map = json.decode(jsonStr);
        final histItem = HistoryItem.fromJson(map);
        return !histItem.isExpired;
      } catch (e) {
        return false; // Remove corrupted items
      }
    }).toList();

    // Add new item to the beginning
    historyJson.insert(0, json.encode(item.toJson()));

    // Keep only last 100 items
    if (historyJson.length > 100) {
      historyJson.removeRange(100, historyJson.length);
    }

    await prefs.setStringList(_historyKey, historyJson);
  }

  // Find cached scan result for a URL (if within 8 hours)
  // Prioritizes VirusTotal results over ML Model results
  static Future<HistoryItem?> getCachedResult(String url, String type) async {
    final prefs = await SharedPreferences.getInstance();
    final List<String> historyJson = prefs.getStringList(_historyKey) ?? [];

    // Normalize URL for comparison
    final normalizedUrl = url.trim().toLowerCase();

    HistoryItem? mlResult;

    // First pass: Look for VT results, track any ML results found
    for (final jsonStr in historyJson) {
      try {
        final Map<String, dynamic> map = json.decode(jsonStr);
        final item = HistoryItem.fromJson(map);

        // Check if same URL/type and cache is still valid
        if (item.type == type &&
            item.name.trim().toLowerCase() == normalizedUrl &&
            item.isCacheValid) {
          // Check if this is a VT result
          final methodUsed = item.fullData?['method_used'] as String?;

          if (methodUsed == 'VirusTotal') {
            print(
                '[CACHE] Found valid VT result from history for $url (cached until ${item.cacheUntil})');
            return item; // Return VT result immediately
          } else if (methodUsed == 'ML Model' && mlResult == null) {
            // Store first ML result found but keep searching for VT
            mlResult = item;
          }
        }
      } catch (e) {
        continue;
      }
    }

    // If no VT result found but ML result exists, use that
    if (mlResult != null) {
      print(
          '[CACHE] No VT history found, using ML result for $url (cached until ${mlResult.cacheUntil})');
    }

    return mlResult;
  }

  // Find cached file/hash scan result (if within 8 hours)
  // Uses SHA256 hash as identifier since same hash = same file
  static Future<HistoryItem?> getCachedFileResult(
      String identifier, String type) async {
    final prefs = await SharedPreferences.getInstance();
    final List<String> historyJson = prefs.getStringList(_historyKey) ?? [];

    // Normalize identifier (hash or filename) for comparison
    final normalizedId = identifier.trim().toLowerCase();

    for (final jsonStr in historyJson) {
      try {
        final Map<String, dynamic> map = json.decode(jsonStr);
        final item = HistoryItem.fromJson(map);

        // Check if same file/hash and cache is still valid
        if (item.type == type &&
            item.name.trim().toLowerCase() == normalizedId &&
            item.isCacheValid) {
          print(
              '[CACHE] Found valid cached result for $type: $identifier (cached until ${item.cacheUntil})');
          return item;
        }
      } catch (e) {
        continue;
      }
    }

    return null;
  }

  // Load all history items (auto-clean expired items)
  static Future<List<HistoryItem>> loadHistory() async {
    final prefs = await SharedPreferences.getInstance();
    List<String> historyJson = prefs.getStringList(_historyKey) ?? [];

    // Filter out expired items (7+ days)
    final validItems = <HistoryItem>[];
    final validJsonList = <String>[];

    for (final jsonStr in historyJson) {
      try {
        final Map<String, dynamic> map = json.decode(jsonStr);
        final item = HistoryItem.fromJson(map);

        if (!item.isExpired) {
          validItems.add(item);
          validJsonList.add(jsonStr);
        } else {
          print(
              '[CLEANUP] Removing expired item: ${item.name} (expired ${DateTime.now().difference(item.expiresAt).inDays} days ago)');
        }
      } catch (e) {
        // Skip corrupted items
        continue;
      }
    }

    // Save cleaned list back to storage
    if (validJsonList.length != historyJson.length) {
      await prefs.setStringList(_historyKey, validJsonList);
      print(
          '[CLEANUP] Removed ${historyJson.length - validJsonList.length} expired items');
    }

    return validItems;
  }

  // Delete specific history items by IDs
  static Future<void> deleteHistoryItems(List<String> ids) async {
    final prefs = await SharedPreferences.getInstance();
    final List<String> historyJson = prefs.getStringList(_historyKey) ?? [];

    final updatedHistory = historyJson.where((jsonStr) {
      final Map<String, dynamic> map = json.decode(jsonStr);
      return !ids.contains(map['id']);
    }).toList();

    await prefs.setStringList(_historyKey, updatedHistory);
  }

  // Delete all history
  static Future<void> deleteAllHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_historyKey);
  }
}

// URL Expansion Utility - Follows redirects to get final URL
class URLExpander {
  /// Expands shortened/redirect URLs to get the actual final destination URL
  /// Handles: bit.ly, tinyurl, LinkedIn redirects, etc.
  static Future<String> expandURL(String url) async {
    try {
      // Clean up the URL
      String cleanUrl = url.trim();

      // Ensure URL has a scheme
      if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://$cleanUrl';
      }

      print('[DEBUG] Expanding URL: $cleanUrl');

      // Create HTTP client that doesn't automatically follow redirects
      final client = HttpClient();
      client.badCertificateCallback =
          (X509Certificate cert, String host, int port) => true;

      String currentUrl = cleanUrl;
      int redirectCount = 0;
      const maxRedirects = 10; // Prevent infinite loops

      while (redirectCount < maxRedirects) {
        try {
          final uri = Uri.parse(currentUrl);
          final request = await client.getUrl(uri);
          request.followRedirects = false; // Don't auto-follow
          request.headers.set('User-Agent',
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

          final response = await request.close();

          // Check if it's a redirect
          if (response.statusCode >= 300 && response.statusCode < 400) {
            final location = response.headers.value('location');
            if (location != null) {
              print('[DEBUG] Redirect $redirectCount: $location');

              // Handle relative redirects
              if (location.startsWith('/')) {
                currentUrl = '${uri.scheme}://${uri.host}$location';
              } else if (!location.startsWith('http')) {
                currentUrl = '${uri.scheme}://${uri.host}/${location}';
              } else {
                currentUrl = location;
              }

              redirectCount++;
              continue;
            }
          }

          // No more redirects, we've reached the final URL
          print('[DEBUG] Final URL: $currentUrl');
          await response.drain();
          break;
        } catch (e) {
          print('[DEBUG] Error during redirect: $e');
          break;
        }
      }

      client.close();
      return currentUrl;
    } catch (e) {
      print('[ERROR] URL expansion failed: $e');
      return url; // Return original URL if expansion fails
    }
  }
}

void main() {
  runApp(const PhishGuardApp());
}

// Global key for navigation
final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();

class PhishGuardApp extends StatefulWidget {
  const PhishGuardApp({super.key});

  @override
  State<PhishGuardApp> createState() => _PhishGuardAppState();
}

class _PhishGuardAppState extends State<PhishGuardApp> {
  late AppLinks _appLinks;
  StreamSubscription<Uri>? _linkSubscription;

  @override
  void initState() {
    super.initState();
    _initDeepLinks();
  }

  @override
  void dispose() {
    _linkSubscription?.cancel();
    super.dispose();
  }

  Future<void> _initDeepLinks() async {
    _appLinks = AppLinks();

    // Handle the initial link if app was opened from a link
    try {
      final initialUri = await _appLinks.getInitialAppLink();
      if (initialUri != null) {
        _handleIncomingLink(initialUri);
      }
    } catch (e) {
      print('[ERROR] Failed to get initial link: $e');
    }

    // Handle links while app is running
    _linkSubscription = _appLinks.uriLinkStream.listen(
      (uri) {
        _handleIncomingLink(uri);
      },
      onError: (err) {
        print('[ERROR] Deep link error: $err');
      },
    );
  }

  Future<void> _handleIncomingLink(Uri uri) async {
    print('[DEBUG] Received deep link: $uri');

    // Extract the URL
    String incomingUrl = uri.toString();

    // Expand the URL to follow any redirects
    final expandedUrl = await URLExpander.expandURL(incomingUrl);

    print('[DEBUG] Expanded URL: $expandedUrl');

    // Navigate to URL scanner page and paste the URL
    // Small delay to ensure the app UI is ready
    await Future.delayed(const Duration(milliseconds: 500));

    if (navigatorKey.currentState != null) {
      // Navigate directly to the CheckURLPage with the expanded URL
      navigatorKey.currentState!.pushAndRemoveUntil(
        MaterialPageRoute(
          builder: (context) => Scaffold(
            backgroundColor: const Color(0xFF1a1d2e),
            appBar: AppBar(
              backgroundColor: const Color(0xFF2a3346),
              title: const Text('PhishGuard - URL Scanner',
                  style: TextStyle(color: Colors.white)),
              leading: IconButton(
                icon: const Icon(Icons.arrow_back, color: Colors.white),
                onPressed: () {
                  Navigator.pushReplacement(
                    context,
                    MaterialPageRoute(
                      builder: (context) => const PhishGuardHomePage(),
                    ),
                  );
                },
              ),
            ),
            body: CheckURLPage(initialUrl: expandedUrl),
          ),
        ),
        (route) => false,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PhishGuard',
      debugShowCheckedModeBanner: false, // Remove debug banner
      navigatorKey: navigatorKey,
      theme: ThemeData(
        primarySwatch: Colors.blue,
        scaffoldBackgroundColor: const Color(0xFF1a1d2e),
      ),
      home: const PhishGuardHomePage(),
    );
  }
}

class PhishGuardHomePage extends StatelessWidget {
  const PhishGuardHomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 20),
              // Title with icons
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  const Text(
                    'PhishGuard',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 28,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  Row(
                    children: [
                      IconButton(
                        icon: const Icon(Icons.history, color: Colors.white),
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => const ScanHistoryPage(),
                            ),
                          );
                        },
                      ),
                      IconButton(
                        icon: const Icon(Icons.settings, color: Colors.white),
                        onPressed: () {
                          Navigator.push(
                            context,
                            MaterialPageRoute(
                              builder: (context) => const SettingsPage(),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 40),
              // Info Card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: const Color(0xFF5a7c9e),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: const Color(0xFF4a6c8e),
                    width: 2,
                  ),
                ),
                child: Column(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        shape: BoxShape.circle,
                      ),
                      child: const Icon(
                        Icons.shield,
                        color: Colors.white,
                        size: 40,
                      ),
                    ),
                    const SizedBox(height: 16),
                    const Text(
                      'Your Anti-Phishing Assistant',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Scan QR codes, check links and verify files before opening',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 14,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 32),
              // Feature Buttons
              _buildFeatureButton(
                icon: Icons.qr_code_scanner,
                title: 'Scan QR Code',
                subtitle: 'Detect malicious QR payloads',
                onTap: () {},
              ),
              const SizedBox(height: 16),
              _buildFeatureButton(
                icon: Icons.link,
                title: 'Check URL',
                subtitle: 'Analyze links for phishing',
                onTap: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => const CheckURLPage(),
                    ),
                  );
                },
              ),
              const SizedBox(height: 16),
              _buildFeatureButton(
                icon: Icons.attach_file,
                title: 'Scan Attachment/Scan File Hash',
                subtitle: 'Verify file safety or check hash',
                onTap: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => const ScanAttachmentPage(),
                    ),
                  );
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildFeatureButton({
    required IconData icon,
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: const Color(0xFF3a5571),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(
                icon,
                color: Colors.white,
                size: 28,
              ),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    subtitle,
                    style: TextStyle(
                      color: Colors.white.withOpacity(0.7),
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(
              Icons.chevron_right,
              color: Colors.white,
              size: 28,
            ),
          ],
        ),
      ),
    );
  }
}

class ScanHistoryPage extends StatefulWidget {
  const ScanHistoryPage({super.key});

  @override
  State<ScanHistoryPage> createState() => _ScanHistoryPageState();
}

class _ScanHistoryPageState extends State<ScanHistoryPage> {
  List<HistoryItem> _historyItems = [];
  bool _isLoading = true;
  bool _isSelectionMode = false;
  Set<String> _selectedIds = {};

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  Future<void> _loadHistory() async {
    final items = await HistoryManager.loadHistory();
    setState(() {
      _historyItems = items;
      _isLoading = false;
    });
  }

  void _toggleItemSelection(String id) {
    setState(() {
      if (_selectedIds.contains(id)) {
        _selectedIds.remove(id);
        // Exit selection mode if no items are selected
        if (_selectedIds.isEmpty) {
          _isSelectionMode = false;
        }
      } else {
        _selectedIds.add(id);
      }
    });
  }

  void _selectAll() {
    setState(() {
      _selectedIds = _historyItems.map((item) => item.id).toSet();
    });
  }

  void _deselectAll() {
    setState(() {
      _selectedIds.clear();
      _isSelectionMode = false;
    });
  }

  Future<void> _deleteSelected() async {
    if (_selectedIds.isEmpty) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF2a3346),
        title: const Text(
          'Delete History',
          style: TextStyle(color: Colors.white),
        ),
        content: Text(
          'Are you sure you want to delete ${_selectedIds.length} item(s)?',
          style: const TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await HistoryManager.deleteHistoryItems(_selectedIds.toList());
      setState(() {
        _historyItems.removeWhere((item) => _selectedIds.contains(item.id));
        _selectedIds.clear();
        _isSelectionMode = false;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('History deleted successfully'),
            backgroundColor: Colors.green,
            duration: Duration(seconds: 2),
          ),
        );
      }
    }
  }

  Future<void> _deleteAll() async {
    if (_historyItems.isEmpty) return;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF2a3346),
        title: const Text(
          'Delete All History',
          style: TextStyle(color: Colors.white),
        ),
        content: const Text(
          'Are you sure you want to delete all scan history? This action cannot be undone.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
            ),
            child: const Text('Delete All'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await HistoryManager.deleteAllHistory();
      setState(() {
        _historyItems.clear();
        _selectedIds.clear();
        _isSelectionMode = false;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('All history deleted successfully'),
            backgroundColor: Colors.green,
            duration: Duration(seconds: 2),
          ),
        );
      }
    }
  }

  String _formatTimestamp(DateTime timestamp) {
    final now = DateTime.now();
    final difference = now.difference(timestamp);

    if (difference.inMinutes < 1) {
      return 'Just now';
    } else if (difference.inHours < 1) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inDays < 1) {
      return '${difference.inHours}h ago';
    } else if (difference.inDays < 7) {
      return '${difference.inDays}d ago';
    } else {
      return DateFormat('MMM d, y').format(timestamp);
    }
  }

  Color _getVerdictColor(String verdict) {
    switch (verdict.toLowerCase()) {
      case 'safe':
        return Colors.green;
      case 'malicious':
        return Colors.red;
      default:
        return Colors.orange;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 20),
              // Header with back button and title
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Container(
                        decoration: BoxDecoration(
                          border: Border.all(
                            color: const Color(0xFF4a9eff),
                            width: 2,
                          ),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: IconButton(
                          icon: const Icon(
                            Icons.arrow_back,
                            color: Color(0xFF4a9eff),
                          ),
                          onPressed: () {
                            Navigator.pop(context);
                          },
                          padding: const EdgeInsets.all(8),
                          constraints: const BoxConstraints(),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Text(
                        _isSelectionMode
                            ? '${_selectedIds.length} selected'
                            : 'Scan History',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 24,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                  Container(
                    decoration: BoxDecoration(
                      border: Border.all(
                        color: _isSelectionMode ? Colors.red : Colors.white,
                        width: 2,
                      ),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: IconButton(
                      icon: Icon(
                        _isSelectionMode ? Icons.delete : Icons.delete_outline,
                        color: _isSelectionMode ? Colors.red : Colors.white,
                      ),
                      onPressed:
                          _isSelectionMode ? _deleteSelected : _deleteAll,
                      padding: const EdgeInsets.all(8),
                      constraints: const BoxConstraints(),
                    ),
                  ),
                ],
              ),

              // Selection mode actions
              if (_isSelectionMode) ...[
                const SizedBox(height: 16),
                Row(
                  children: [
                    TextButton.icon(
                      onPressed: _selectAll,
                      icon: const Icon(Icons.select_all,
                          color: Color(0xFF4a9eff)),
                      label: const Text(
                        'Select All',
                        style: TextStyle(color: Color(0xFF4a9eff)),
                      ),
                    ),
                    const SizedBox(width: 16),
                    TextButton.icon(
                      onPressed: _deselectAll,
                      icon: const Icon(Icons.clear, color: Colors.grey),
                      label: const Text(
                        'Cancel',
                        style: TextStyle(color: Colors.grey),
                      ),
                    ),
                  ],
                ),
              ],

              const SizedBox(height: 32),

              // History Items
              Expanded(
                child: _isLoading
                    ? const Center(
                        child: CircularProgressIndicator(
                          color: Color(0xFF4a9eff),
                        ),
                      )
                    : _historyItems.isEmpty
                        ? Center(
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              children: [
                                Icon(
                                  Icons.history,
                                  size: 64,
                                  color: Colors.white.withOpacity(0.3),
                                ),
                                const SizedBox(height: 16),
                                Text(
                                  'No scan history yet',
                                  style: TextStyle(
                                    color: Colors.white.withOpacity(0.5),
                                    fontSize: 18,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'Your scans will appear here',
                                  style: TextStyle(
                                    color: Colors.white.withOpacity(0.3),
                                    fontSize: 14,
                                  ),
                                ),
                              ],
                            ),
                          )
                        : ListView.builder(
                            itemCount: _historyItems.length,
                            itemBuilder: (context, index) {
                              final item = _historyItems[index];
                              final isSelected = _selectedIds.contains(item.id);

                              return Padding(
                                padding: const EdgeInsets.only(bottom: 16),
                                child: GestureDetector(
                                  onTap: () {
                                    if (_isSelectionMode) {
                                      _toggleItemSelection(item.id);
                                    } else {
                                      // Navigate to detail page
                                      Navigator.push(
                                        context,
                                        MaterialPageRoute(
                                          builder: (context) =>
                                              HistoryDetailPage(
                                            item: item,
                                          ),
                                        ),
                                      );
                                    }
                                  },
                                  onLongPress: () {
                                    if (!_isSelectionMode) {
                                      setState(() {
                                        _isSelectionMode = true;
                                        _selectedIds.add(item.id);
                                      });
                                    }
                                  },
                                  child: Container(
                                    padding: const EdgeInsets.all(20),
                                    decoration: BoxDecoration(
                                      color: isSelected
                                          ? const Color(0xFF4a6c8e)
                                          : const Color(0xFF5a7c9e),
                                      borderRadius: BorderRadius.circular(8),
                                      border: isSelected
                                          ? Border.all(
                                              color: const Color(0xFF4a9eff),
                                              width: 2,
                                            )
                                          : null,
                                    ),
                                    child: Row(
                                      children: [
                                        if (_isSelectionMode)
                                          Padding(
                                            padding: const EdgeInsets.only(
                                                right: 12),
                                            child: Icon(
                                              isSelected
                                                  ? Icons.check_circle
                                                  : Icons.circle_outlined,
                                              color: isSelected
                                                  ? const Color(0xFF4a9eff)
                                                  : Colors.white
                                                      .withOpacity(0.5),
                                              size: 24,
                                            ),
                                          ),
                                        Expanded(
                                          child: Column(
                                            crossAxisAlignment:
                                                CrossAxisAlignment.start,
                                            children: [
                                              Row(
                                                children: [
                                                  Container(
                                                    padding: const EdgeInsets
                                                        .symmetric(
                                                      horizontal: 8,
                                                      vertical: 4,
                                                    ),
                                                    decoration: BoxDecoration(
                                                      color: _getVerdictColor(
                                                              item.verdict)
                                                          .withOpacity(0.2),
                                                      borderRadius:
                                                          BorderRadius.circular(
                                                              4),
                                                      border: Border.all(
                                                        color: _getVerdictColor(
                                                            item.verdict),
                                                        width: 1,
                                                      ),
                                                    ),
                                                    child: Text(
                                                      item.type,
                                                      style: TextStyle(
                                                        color: _getVerdictColor(
                                                            item.verdict),
                                                        fontSize: 12,
                                                        fontWeight:
                                                            FontWeight.bold,
                                                      ),
                                                    ),
                                                  ),
                                                  const SizedBox(width: 8),
                                                  Icon(
                                                    item.verdict.toLowerCase() ==
                                                            'safe'
                                                        ? Icons.check_circle
                                                        : item.verdict
                                                                    .toLowerCase() ==
                                                                'malicious'
                                                            ? Icons.warning
                                                            : Icons
                                                                .help_outline,
                                                    size: 16,
                                                    color: _getVerdictColor(
                                                        item.verdict),
                                                  ),
                                                  const SizedBox(width: 6),
                                                  Text(
                                                    item.verdict,
                                                    style: TextStyle(
                                                      color: _getVerdictColor(
                                                          item.verdict),
                                                      fontSize: 14,
                                                      fontWeight:
                                                          FontWeight.w600,
                                                    ),
                                                  ),
                                                ],
                                              ),
                                              const SizedBox(height: 8),
                                              // URL/File with copy button
                                              Row(
                                                children: [
                                                  Expanded(
                                                    child: SelectableText(
                                                      // Show filename for files, URL for URLs
                                                      (item.type == 'File' ||
                                                                  item.type ==
                                                                      'Hash') &&
                                                              (item.fullData
                                                                      ?.containsKey(
                                                                          'display_name') ??
                                                                  false)
                                                          ? item.fullData![
                                                              'display_name']
                                                          : item.name,
                                                      style: const TextStyle(
                                                        color: Colors.white,
                                                        fontSize: 13,
                                                      ),
                                                      maxLines: 2,
                                                    ),
                                                  ),
                                                  const SizedBox(width: 8),
                                                  GestureDetector(
                                                    onTap: () {
                                                      // Copy filename for files, URL/hash for others
                                                      final copyText = (item
                                                                          .type ==
                                                                      'File' ||
                                                                  item.type ==
                                                                      'Hash') &&
                                                              (item.fullData
                                                                      ?.containsKey(
                                                                          'display_name') ??
                                                                  false)
                                                          ? item.fullData![
                                                              'display_name']
                                                          : item.name;
                                                      Clipboard.setData(
                                                          ClipboardData(
                                                              text: copyText));
                                                      ScaffoldMessenger.of(
                                                              context)
                                                          .showSnackBar(
                                                        SnackBar(
                                                          content: Text(item
                                                                      .type ==
                                                                  'URL'
                                                              ? 'URL copied to clipboard'
                                                              : 'File name copied to clipboard'),
                                                          duration:
                                                              const Duration(
                                                                  seconds: 2),
                                                        ),
                                                      );
                                                    },
                                                    child: Container(
                                                      padding:
                                                          const EdgeInsets.all(
                                                              6),
                                                      decoration: BoxDecoration(
                                                        color: const Color(
                                                                0xFF4a9eff)
                                                            .withOpacity(0.2),
                                                        borderRadius:
                                                            BorderRadius
                                                                .circular(4),
                                                      ),
                                                      child: const Icon(
                                                        Icons.copy,
                                                        size: 16,
                                                        color:
                                                            Color(0xFF4a9eff),
                                                      ),
                                                    ),
                                                  ),
                                                ],
                                              ),
                                              const SizedBox(height: 6),
                                              Row(
                                                mainAxisAlignment:
                                                    MainAxisAlignment
                                                        .spaceBetween,
                                                children: [
                                                  Expanded(
                                                    child: Text(
                                                      item.detectionStats,
                                                      style: const TextStyle(
                                                        color: Colors.white70,
                                                        fontSize: 12,
                                                      ),
                                                    ),
                                                  ),
                                                  Text(
                                                    _formatTimestamp(
                                                        item.timestamp),
                                                    style: const TextStyle(
                                                      color: Colors.white60,
                                                      fontSize: 11,
                                                    ),
                                                  ),
                                                ],
                                              ),
                                              const SizedBox(height: 4),
                                              // Expiry countdown
                                              Row(
                                                children: [
                                                  Icon(
                                                    Icons.timer_outlined,
                                                    size: 12,
                                                    color:
                                                        item.daysUntilDeletion <=
                                                                2
                                                            ? Colors.orange
                                                            : Colors.white60,
                                                  ),
                                                  const SizedBox(width: 4),
                                                  Text(
                                                    item.daysUntilDeletion == 0
                                                        ? 'Expires today'
                                                        : 'Expires in ${item.daysUntilDeletion} ${item.daysUntilDeletion == 1 ? 'day' : 'days'}',
                                                    style: TextStyle(
                                                      color:
                                                          item.daysUntilDeletion <=
                                                                  2
                                                              ? Colors.orange
                                                              : Colors.white60,
                                                      fontSize: 11,
                                                      fontStyle:
                                                          FontStyle.italic,
                                                    ),
                                                  ),
                                                ],
                                              ),
                                            ],
                                          ),
                                        ),
                                        if (!_isSelectionMode)
                                          const Icon(
                                            Icons.chevron_right,
                                            color: Colors.white,
                                            size: 28,
                                          ),
                                      ],
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// History Detail Page - Shows full scan details
class HistoryDetailPage extends StatelessWidget {
  final HistoryItem item;

  const HistoryDetailPage({
    super.key,
    required this.item,
  });

  Color _getVerdictColor(String verdict) {
    switch (verdict.toLowerCase()) {
      case 'safe':
        return Colors.green;
      case 'malicious':
        return Colors.red;
      default:
        return Colors.orange;
    }
  }

  @override
  Widget build(BuildContext context) {
    Map<String, dynamic> scanResults = {};
    bool isNotFound = item.verdict.toLowerCase() == 'unknown';

    // Parse full data if available
    if (item.fullData != null &&
        item.fullData!['data'] != null &&
        item.fullData!['data']['attributes'] != null) {
      try {
        final data = item.fullData!['data'] as Map<String, dynamic>?;
        final attributes = data?['attributes'] as Map<String, dynamic>?;

        if (attributes != null) {
          final results = attributes['last_analysis_results'];
          if (results != null) {
            scanResults = Map<String, dynamic>.from(results as Map);
          }
        }
      } catch (e) {
        print('Error parsing VT data: $e');
      }
    }

    Color verdictColor = _getVerdictColor(item.verdict);

    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: Column(
          children: [
            // Header
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: verdictColor,
              ),
              child: Column(
                children: [
                  Row(
                    children: [
                      Container(
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: IconButton(
                          icon: const Icon(
                            Icons.arrow_back,
                            color: Colors.white,
                          ),
                          onPressed: () {
                            Navigator.pop(context);
                          },
                          padding: const EdgeInsets.all(8),
                          constraints: const BoxConstraints(),
                        ),
                      ),
                      const Spacer(),
                      Icon(
                        item.verdict.toLowerCase() == 'safe'
                            ? Icons.check_circle
                            : item.verdict.toLowerCase() == 'malicious'
                                ? Icons.warning
                                : Icons.help_outline,
                        color: Colors.white,
                        size: 48,
                      ),
                      const Spacer(),
                      const SizedBox(width: 48), // Balance for back button
                    ],
                  ),
                  const SizedBox(height: 16),
                  Text(
                    item.verdict,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 28,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    item.detectionStats,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                    ),
                  ),
                  const SizedBox(height: 16),
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: Colors.white.withOpacity(0.2),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      item.type,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            // Content
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // File/Hash Name
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            item.type == 'URL' ? 'URL' : 'File Name',
                            style: const TextStyle(
                              color: Colors.white60,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            // Show filename for files, URL for URLs
                            (item.type == 'File' || item.type == 'Hash') &&
                                    (item.fullData
                                            ?.containsKey('display_name') ??
                                        false)
                                ? item.fullData!['display_name']
                                : item.name,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 14,
                              fontFamily: 'monospace',
                            ),
                          ),
                          // Show hash below filename for files
                          if ((item.type == 'File' || item.type == 'Hash') &&
                              (item.fullData?.containsKey('display_name') ??
                                  false)) ...[
                            const SizedBox(height: 12),
                            const Text(
                              'SHA-256 Hash',
                              style: TextStyle(
                                color: Colors.white60,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 8),
                            SelectableText(
                              item.name,
                              style: const TextStyle(
                                color: Colors.white70,
                                fontSize: 12,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),

                    const SizedBox(height: 16),

                    // Timestamp
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Scanned',
                            style: TextStyle(
                              color: Colors.white60,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Text(
                            DateFormat('MMMM d, y - h:mm a')
                                .format(item.timestamp),
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 14,
                            ),
                          ),
                        ],
                      ),
                    ),

                    if (!isNotFound && scanResults.isNotEmpty) ...[
                      const SizedBox(height: 24),
                      const Text(
                        'Detection Details',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 20,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                      const SizedBox(height: 16),

                      // Vendor Results
                      ...scanResults.entries.map((entry) {
                        final vendor = entry.key;
                        final result = entry.value as Map<String, dynamic>;
                        final category = result['category'] as String?;
                        final detected =
                            category == 'malicious' || category == 'suspicious';

                        return Padding(
                          padding: const EdgeInsets.only(bottom: 12),
                          child: Container(
                            padding: const EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: const Color(0xFF2a3346),
                              borderRadius: BorderRadius.circular(8),
                              border: detected
                                  ? Border.all(
                                      color: Colors.red.withOpacity(0.5),
                                      width: 1,
                                    )
                                  : null,
                            ),
                            child: Row(
                              children: [
                                Icon(
                                  detected ? Icons.warning : Icons.check_circle,
                                  color: detected ? Colors.red : Colors.green,
                                  size: 20,
                                ),
                                const SizedBox(width: 12),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        vendor,
                                        style: const TextStyle(
                                          color: Colors.white,
                                          fontSize: 14,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                      const SizedBox(height: 4),
                                      Text(
                                        result['result']?.toString() ??
                                            category ??
                                            'clean',
                                        style: TextStyle(
                                          color: detected
                                              ? Colors.red
                                              : Colors.green,
                                          fontSize: 13,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      }).toList(),
                    ],

                    if (isNotFound)
                      Padding(
                        padding: const EdgeInsets.only(top: 24),
                        child: Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(20),
                          decoration: BoxDecoration(
                            color: Colors.orange.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: Colors.orange,
                              width: 1,
                            ),
                          ),
                          child: const Column(
                            children: [
                              Icon(
                                Icons.info_outline,
                                color: Colors.orange,
                                size: 48,
                              ),
                              SizedBox(height: 12),
                              Text(
                                'No data found in VirusTotal database',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 16,
                                ),
                                textAlign: TextAlign.center,
                              ),
                              SizedBox(height: 8),
                              Text(
                                'This item has not been scanned before',
                                style: TextStyle(
                                  color: Colors.white70,
                                  fontSize: 14,
                                ),
                                textAlign: TextAlign.center,
                              ),
                            ],
                          ),
                        ),
                      ),

                    const SizedBox(height: 40),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final TextEditingController _apiKeyController = TextEditingController();
  final TextEditingController _backendUrlController = TextEditingController();
  bool _isApiKeyConfigured = false;
  bool _isBackendUrlConfigured = false;
  bool _isPasswordVisible = false;

  @override
  void initState() {
    super.initState();
    _loadApiKey();
    _loadBackendUrl();
  }

  Future<void> _loadApiKey() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final apiKey = prefs.getString('virustotal_api_key');

      if (apiKey != null && apiKey.isNotEmpty) {
        setState(() {
          _apiKeyController.text = apiKey;
          _isApiKeyConfigured = true;
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error loading API key: ${e.toString()}'),
            backgroundColor: Colors.orange,
          ),
        );
      }
    }
  }

  Future<void> _loadBackendUrl() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final backendUrl = prefs.getString('backend_url') ??
          'https://phishguard-ml-backend.onrender.com';

      setState(() {
        _backendUrlController.text = backendUrl;
        _isBackendUrlConfigured = backendUrl.isNotEmpty;
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error loading backend URL: ${e.toString()}'),
            backgroundColor: Colors.orange,
          ),
        );
      }
    }
  }

  @override
  void dispose() {
    _apiKeyController.dispose();
    _backendUrlController.dispose();
    super.dispose();
  }

  Future<void> _saveApiKey() async {
    if (_apiKeyController.text.isNotEmpty) {
      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('virustotal_api_key', _apiKeyController.text);

        setState(() {
          _isApiKeyConfigured = true;
        });

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('API Key saved successfully'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Error saving API key: ${e.toString()}'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter an API key'),
          backgroundColor: Colors.orange,
        ),
      );
    }
  }

  Future<void> _deleteApiKey() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove('virustotal_api_key');

      setState(() {
        _apiKeyController.clear();
        _isApiKeyConfigured = false;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('API Key deleted'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error deleting API key: ${e.toString()}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _saveBackendUrl() async {
    if (_backendUrlController.text.isNotEmpty) {
      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('backend_url', _backendUrlController.text);

        setState(() {
          _isBackendUrlConfigured = true;
        });

        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Backend URL saved successfully'),
              backgroundColor: Colors.green,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Error saving backend URL: ${e.toString()}'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter a backend URL'),
          backgroundColor: Colors.orange,
        ),
      );
    }
  }

  Future<void> _resetBackendUrl() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(
          'backend_url', 'https://phishguard-ml-backend.onrender.com');

      setState(() {
        _backendUrlController.text =
            'https://phishguard-ml-backend.onrender.com';
        _isBackendUrlConfigured = true;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Backend URL reset to localhost'),
            backgroundColor: Colors.blue,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error resetting backend URL: ${e.toString()}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: Column(
          children: [
            // Header
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: const BoxDecoration(
                color: Color(0xFF5a7c9e),
                border: Border(
                  bottom: BorderSide(
                    color: Color(0xFF4a9eff),
                    width: 3,
                  ),
                ),
              ),
              child: Row(
                children: [
                  IconButton(
                    icon: const Icon(
                      Icons.arrow_back,
                      color: Colors.white,
                      size: 28,
                    ),
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                  const SizedBox(width: 16),
                  const Text(
                    'Settings',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
            // Content
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // VirusTotal Integration Section
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(8),
                                decoration: BoxDecoration(
                                  color: Colors.white.withOpacity(0.1),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: const Icon(
                                  Icons.shield,
                                  color: Colors.white,
                                  size: 24,
                                ),
                              ),
                              const SizedBox(width: 12),
                              const Text(
                                'VirusTotal Integration',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 18,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          const Text(
                            'Add your VirusTotal API key to check URLs against 70+ security vendors',
                            style: TextStyle(
                              color: Colors.white70,
                              fontSize: 13,
                            ),
                          ),
                          const SizedBox(height: 20),
                          // API Key Input
                          Container(
                            decoration: BoxDecoration(
                              color: const Color(0xFF1a1d2e),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            padding: const EdgeInsets.symmetric(horizontal: 12),
                            child: Row(
                              children: [
                                const Icon(
                                  Icons.vpn_key,
                                  color: Colors.white54,
                                  size: 20,
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: TextField(
                                    controller: _apiKeyController,
                                    obscureText: !_isPasswordVisible,
                                    style: const TextStyle(color: Colors.white),
                                    decoration: const InputDecoration(
                                      hintText: 'Enter API Key',
                                      hintStyle:
                                          TextStyle(color: Colors.white38),
                                      border: InputBorder.none,
                                    ),
                                  ),
                                ),
                                IconButton(
                                  icon: Icon(
                                    _isPasswordVisible
                                        ? Icons.visibility
                                        : Icons.visibility_off,
                                    color: Colors.white54,
                                    size: 20,
                                  ),
                                  onPressed: () {
                                    setState(() {
                                      _isPasswordVisible = !_isPasswordVisible;
                                    });
                                  },
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 16),
                          // API Key Configured Status
                          if (_isApiKeyConfigured)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 12,
                              ),
                              decoration: BoxDecoration(
                                color: Colors.green.withOpacity(0.1),
                                border: Border.all(
                                  color: Colors.green,
                                  width: 1,
                                ),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.all(4),
                                    decoration: const BoxDecoration(
                                      color: Colors.green,
                                      shape: BoxShape.circle,
                                    ),
                                    child: const Icon(
                                      Icons.check,
                                      color: Colors.white,
                                      size: 16,
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  const Text(
                                    'API key configured',
                                    style: TextStyle(
                                      color: Colors.green,
                                      fontSize: 14,
                                      fontWeight: FontWeight.w500,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          const SizedBox(height: 16),
                          // Save and Delete Buttons
                          Row(
                            children: [
                              Expanded(
                                child: ElevatedButton.icon(
                                  onPressed: _saveApiKey,
                                  icon: const Icon(
                                    Icons.save,
                                    color: Colors.white,
                                    size: 18,
                                  ),
                                  label: const Text(
                                    'Save Key',
                                    style: TextStyle(
                                      color: Colors.white,
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: const Color(0xFF4a6c8e),
                                    padding: const EdgeInsets.symmetric(
                                      vertical: 12,
                                    ),
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(8),
                                    ),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 12),
                              ElevatedButton.icon(
                                onPressed: _deleteApiKey,
                                icon: const Icon(
                                  Icons.delete,
                                  color: Colors.white,
                                  size: 18,
                                ),
                                label: const Text(
                                  'Delete',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: Colors.red,
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 20,
                                    vertical: 12,
                                  ),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),

                    // Backend URL Configuration Section
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(8),
                                decoration: BoxDecoration(
                                  color: Colors.white.withOpacity(0.1),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: const Icon(
                                  Icons.cloud,
                                  color: Colors.white,
                                  size: 24,
                                ),
                              ),
                              const SizedBox(width: 12),
                              const Text(
                                'Backend Configuration',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 18,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          const Text(
                            'Enter your backend URL (localhost or ngrok URL for remote access)',
                            style: TextStyle(
                              color: Colors.white70,
                              fontSize: 13,
                            ),
                          ),
                          const SizedBox(height: 20),
                          // Backend URL Input
                          Container(
                            decoration: BoxDecoration(
                              color: const Color(0xFF1a1d2e),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            padding: const EdgeInsets.symmetric(horizontal: 12),
                            child: Row(
                              children: [
                                const Icon(
                                  Icons.link,
                                  color: Colors.white54,
                                  size: 20,
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: TextField(
                                    controller: _backendUrlController,
                                    style: const TextStyle(color: Colors.white),
                                    decoration: const InputDecoration(
                                      hintText:
                                          'http://localhost:8000 or https://your-ngrok-url',
                                      hintStyle: TextStyle(
                                          color: Colors.white38, fontSize: 13),
                                      border: InputBorder.none,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 16),
                          // Backend URL Configured Status
                          if (_isBackendUrlConfigured)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 12,
                              ),
                              decoration: BoxDecoration(
                                color: Colors.blue.withOpacity(0.1),
                                border: Border.all(
                                  color: Colors.blue,
                                  width: 1,
                                ),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Row(
                                children: [
                                  Container(
                                    padding: const EdgeInsets.all(4),
                                    decoration: const BoxDecoration(
                                      color: Colors.blue,
                                      shape: BoxShape.circle,
                                    ),
                                    child: const Icon(
                                      Icons.check,
                                      color: Colors.white,
                                      size: 16,
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Text(
                                      'Backend: ${_backendUrlController.text}',
                                      style: const TextStyle(
                                        color: Colors.blue,
                                        fontSize: 13,
                                        fontWeight: FontWeight.w500,
                                      ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          const SizedBox(height: 16),
                          // Save and Reset Buttons
                          Row(
                            children: [
                              Expanded(
                                child: ElevatedButton.icon(
                                  onPressed: _saveBackendUrl,
                                  icon: const Icon(
                                    Icons.save,
                                    color: Colors.white,
                                    size: 18,
                                  ),
                                  label: const Text(
                                    'Save URL',
                                    style: TextStyle(
                                      color: Colors.white,
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: const Color(0xFF4a6c8e),
                                    padding: const EdgeInsets.symmetric(
                                      vertical: 12,
                                    ),
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(8),
                                    ),
                                  ),
                                ),
                              ),
                              const SizedBox(width: 12),
                              ElevatedButton.icon(
                                onPressed: _resetBackendUrl,
                                icon: const Icon(
                                  Icons.refresh,
                                  color: Colors.white,
                                  size: 18,
                                ),
                                label: const Text(
                                  'Reset',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: Colors.orange,
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 20,
                                    vertical: 12,
                                  ),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          // Info text
                          Container(
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: Colors.blue.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Icon(
                                  Icons.info_outline,
                                  color: Colors.blue[300],
                                  size: 18,
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text(
                                    'Use localhost for same device testing, or ngrok URL for remote access from other devices',
                                    style: TextStyle(
                                      color: Colors.blue[200],
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),

                    // About PhishGuard Section
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: Colors.white.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: const Icon(
                              Icons.info_outline,
                              color: Colors.white,
                              size: 24,
                            ),
                          ),
                          const SizedBox(width: 12),
                          Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text(
                                'About PhishGuard',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                'Version 1.0.0',
                                style: TextStyle(
                                  color: Colors.white.withOpacity(0.7),
                                  fontSize: 13,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// Rate Limit Dialog with Countdown
class RateLimitDialog extends StatefulWidget {
  final int secondsUntilReset;

  const RateLimitDialog({super.key, required this.secondsUntilReset});

  @override
  State<RateLimitDialog> createState() => _RateLimitDialogState();
}

class _RateLimitDialogState extends State<RateLimitDialog> {
  late int _remainingSeconds;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _remainingSeconds = widget.secondsUntilReset;

    // Start countdown timer
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      setState(() {
        _remainingSeconds--;
        if (_remainingSeconds <= 0) {
          timer.cancel();
          Navigator.of(context).pop(); // Auto-close when reset
        }
      });
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final minutes = _remainingSeconds ~/ 60;
    final seconds = _remainingSeconds % 60;

    return AlertDialog(
      backgroundColor: const Color(0xFF2a3346),
      title: Row(
        children: [
          Icon(Icons.timer_off, color: Colors.orange, size: 28),
          const SizedBox(width: 12),
          const Text(
            'Rate Limit Exceeded',
            style: TextStyle(color: Colors.white),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.orange.withOpacity(0.2),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Colors.orange, width: 2),
            ),
            child: Column(
              children: [
                Text(
                  'VirusTotal API Limit',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Maximum 4 requests per minute',
                  style: TextStyle(
                    color: Colors.white70,
                    fontSize: 14,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'Limit resets in:',
            style: TextStyle(
              color: Colors.white70,
              fontSize: 14,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}',
            style: TextStyle(
              color: Colors.orange,
              fontSize: 48,
              fontWeight: FontWeight.bold,
              fontFeatures: [FontFeature.tabularFigures()],
            ),
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF1a1d2e),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.lightbulb_outline, color: Colors.blue, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'ML Model will be used as fallback during rate limits',
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text(
            'OK',
            style: TextStyle(color: Color(0xFF4a9eff)),
          ),
        ),
      ],
    );
  }
}

// Check URL Page
class CheckURLPage extends StatefulWidget {
  final String? initialUrl;

  const CheckURLPage({super.key, this.initialUrl});

  @override
  State<CheckURLPage> createState() => _CheckURLPageState();
}

class _CheckURLPageState extends State<CheckURLPage> {
  final TextEditingController _urlController = TextEditingController();
  bool _isChecking = false;
  String _backendUrl = 'http://localhost:8000'; // Default backend URL

  @override
  void initState() {
    super.initState();
    _loadBackendUrl();

    // If an initial URL is provided, paste it into the text field
    if (widget.initialUrl != null && widget.initialUrl!.isNotEmpty) {
      _urlController.text = widget.initialUrl!;

      // Show a dialog to inform the user
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _showURLReceivedDialog();
      });
    }
  }

  void _showURLReceivedDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF2a3346),
        title: const Row(
          children: [
            Icon(Icons.link, color: Color(0xFF4a9eff)),
            SizedBox(width: 8),
            Text('URL Received', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'A URL has been pasted into the scanner. Review it and click "Scan URL" to check for threats.',
              style: TextStyle(color: Colors.white70),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0xFF1a1d2e),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                widget.initialUrl!,
                style: const TextStyle(
                  color: Color(0xFF4a9eff),
                  fontSize: 12,
                ),
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('OK', style: TextStyle(color: Color(0xFF4a9eff))),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  Future<void> _loadBackendUrl() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _backendUrl = prefs.getString('backend_url') ?? 'http://localhost:8000';
    });
  }

  void _showRateLimitDialog(int secondsUntilReset) {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) =>
          RateLimitDialog(secondsUntilReset: secondsUntilReset),
    );
  }

  Future<void> _checkUrl() async {
    final url = _urlController.text.trim();

    if (url.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter a URL'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }

    // Basic URL validation
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('URL must start with http:// or https://'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    setState(() {
      _isChecking = true;
    });

    try {
      // Check if we have a cached result for this URL (within 8 hours)
      final cachedResult = await HistoryManager.getCachedResult(url, 'URL');

      if (cachedResult != null) {
        setState(() {
          _isChecking = false;
        });

        print('[CACHE] Using cached result for $url');

        // Show cached result notification
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  Icon(Icons.history, color: Colors.white),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Showing cached result (scanned ${_getTimeAgo(cachedResult.timestamp)})',
                    ),
                  ),
                ],
              ),
              backgroundColor: Colors.blue,
              duration: const Duration(seconds: 3),
            ),
          );

          // Navigate to cached results page
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (context) => URLResultsPage(
                url: url,
                result: cachedResult.fullData ?? {},
              ),
            ),
          );
        }
        return; // Don't make API call
      }

      // Get stored VT API key and backend URL from SharedPreferences
      final prefs = await SharedPreferences.getInstance();
      final vtApiKey = prefs.getString('virustotal_api_key');

      // Check rate limit status before scanning
      try {
        final rateLimitResponse = await http
            .get(
              Uri.parse('$_backendUrl/rate-limit-status'),
            )
            .timeout(const Duration(seconds: 5));

        if (rateLimitResponse.statusCode == 200) {
          final rateLimitData = json.decode(rateLimitResponse.body);
          final isRateLimited = rateLimitData['rate_limited'] as bool;
          final secondsUntilReset = rateLimitData['seconds_until_reset'] as int;
          final requestsRemaining = rateLimitData['requests_remaining'] as int;

          if (isRateLimited) {
            // Show informational snackbar but DON'T block the scan
            // The backend will use ML model automatically
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Row(
                    children: [
                      Icon(Icons.info_outline, color: Colors.white),
                      SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'VirusTotal rate limited. Using ML Model for analysis...',
                        ),
                      ),
                    ],
                  ),
                  backgroundColor: Colors.orange,
                  duration: const Duration(seconds: 4),
                ),
              );
            }
            // DON'T return - let the scan proceed with ML
          } else if (requestsRemaining <= 1 && requestsRemaining > 0) {
            // Warn if only 1 request left
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text(
                      '⚠️ Only $requestsRemaining VirusTotal request remaining this minute'),
                  backgroundColor: Colors.orange,
                  duration: const Duration(seconds: 3),
                ),
              );
            }
          }
        }
      } catch (e) {
        print('[DEBUG] Could not check rate limit: $e');
        // Continue with scan even if rate limit check fails
      }

      // Prepare request body with URL and optional API key
      final Map<String, dynamic> requestBody = {'url': url};
      if (vtApiKey != null && vtApiKey.isNotEmpty) {
        requestBody['vt_api_key'] = vtApiKey;
      }

      // Call FastAPI backend
      final response = await http
          .post(
        Uri.parse('$_backendUrl/check-url'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode(requestBody),
      )
          .timeout(
        const Duration(seconds: 30),
        onTimeout: () {
          throw TimeoutException('Request timed out');
        },
      );

      setState(() {
        _isChecking = false;
      });

      if (response.statusCode == 200) {
        final Map<String, dynamic> result = json.decode(response.body);

        // Determine cache duration based on method used
        // VirusTotal results: 8 hours (reliable, comprehensive)
        // ML Model results: 30 minutes (allow VT to be tried again soon)
        final methodUsed = result['method_used'] as String?;
        final cacheDuration = (methodUsed == 'VirusTotal')
            ? const Duration(hours: 8)
            : const Duration(minutes: 30);

        // Save to history
        final historyItem = HistoryItem(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'URL',
          name: url,
          verdict: result['verdict'] ?? 'Unknown',
          detectionStats: result['details'] ?? 'No details available',
          timestamp: DateTime.now(),
          cacheUntil: DateTime.now().add(cacheDuration),
          fullData: result,
        );

        await HistoryManager.saveHistoryItem(historyItem);

        // Navigate to results page
        if (mounted) {
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (context) => URLResultsPage(
                url: url,
                result: result,
              ),
            ),
          );
        }
      } else {
        throw Exception('Failed to check URL: ${response.statusCode}');
      }
    } on TimeoutException {
      setState(() {
        _isChecking = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
                'Request timed out. Make sure the backend server is running.'),
            backgroundColor: Colors.red,
            duration: Duration(seconds: 5),
          ),
        );
      }
    } catch (e) {
      setState(() {
        _isChecking = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
                'Error: ${e.toString()}\n\nMake sure the FastAPI backend is running at $_backendUrl'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 6),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      appBar: AppBar(
        backgroundColor: const Color(0xFF2a3346),
        title: const Text('Check URL', style: TextStyle(color: Colors.white)),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings, color: Colors.white),
            onPressed: () {
              _showBackendSettings();
            },
          ),
        ],
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Info Card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: const Color(0xFF5a7c9e),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: const Color(0xFF4a6c8e),
                    width: 2,
                  ),
                ),
                child: Column(
                  children: [
                    Icon(
                      Icons.security,
                      color: Colors.white,
                      size: 48,
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Two-Layer URL Protection',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      '1. VirusTotal API (80+ security vendors)\n2. ML Model (98.17% accuracy)',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 14,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 32),

              // URL Input
              const Text(
                'Enter URL to Check',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.w500,
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _urlController,
                style: const TextStyle(color: Colors.white),
                keyboardType: TextInputType
                    .text, // Use text type to prevent URL auto-correction
                autocorrect: false, // Disable autocorrect
                enableSuggestions: false, // Disable suggestions
                decoration: InputDecoration(
                  hintText: 'https://example.com',
                  hintStyle: TextStyle(color: Colors.white.withOpacity(0.5)),
                  filled: true,
                  fillColor: const Color(0xFF2a3346),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide.none,
                  ),
                  prefixIcon: const Icon(Icons.link, color: Colors.white70),
                  suffixIcon: _urlController.text.isNotEmpty
                      ? IconButton(
                          icon: const Icon(Icons.clear, color: Colors.white70),
                          onPressed: () {
                            _urlController.clear();
                            setState(() {});
                          },
                        )
                      : null,
                ),
                onChanged: (value) {
                  setState(() {});
                },
                enabled: !_isChecking,
              ),
              const SizedBox(height: 24),

              // Check Button
              SizedBox(
                width: double.infinity,
                height: 54,
                child: ElevatedButton(
                  onPressed: _isChecking ? null : _checkUrl,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4a9eff),
                    disabledBackgroundColor: const Color(0xFF3a5571),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  child: _isChecking
                      ? const Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                valueColor:
                                    AlwaysStoppedAnimation<Color>(Colors.white),
                              ),
                            ),
                            SizedBox(width: 12),
                            Text(
                              'Checking URL...',
                              style: TextStyle(
                                fontSize: 16,
                                color: Colors.white,
                              ),
                            ),
                          ],
                        )
                      : const Text(
                          'Check URL',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                            color: Colors.white,
                          ),
                        ),
                ),
              ),
              const SizedBox(height: 24),

              // Info Section
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFF2a3346),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.info_outline, color: Colors.blue[300]),
                        const SizedBox(width: 8),
                        const Text(
                          'How it works',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    _buildInfoRow('1️⃣',
                        'VirusTotal checks URL against 80+ security vendors'),
                    const SizedBox(height: 8),
                    _buildInfoRow('2️⃣',
                        'ML Model analyzes URL patterns for phishing indicators'),
                    const SizedBox(height: 8),
                    _buildInfoRow(
                        '3️⃣', 'Combined verdict with confidence score'),
                  ],
                ),
              ),

              const SizedBox(height: 16),

              // Backend Status
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF2a3346),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(Icons.circle,
                        size: 8,
                        color:
                            _backendUrl.isNotEmpty ? Colors.green : Colors.red),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Backend: $_backendUrl',
                        style: TextStyle(
                          color: Colors.white.withOpacity(0.7),
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInfoRow(String emoji, String text) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(emoji, style: const TextStyle(fontSize: 16)),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            text,
            style: TextStyle(
              color: Colors.white.withOpacity(0.8),
              fontSize: 14,
            ),
          ),
        ),
      ],
    );
  }

  void _showBackendSettings() {
    final TextEditingController backendController =
        TextEditingController(text: _backendUrl);

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF2a3346),
        title: const Text(
          'Backend Settings',
          style: TextStyle(color: Colors.white),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Backend URL:',
              style: TextStyle(color: Colors.white70, fontSize: 14),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: backendController,
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                hintText: 'http://localhost:8000',
                hintStyle: TextStyle(color: Colors.white.withOpacity(0.5)),
                filled: true,
                fillColor: const Color(0xFF1a1d2e),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none,
                ),
              ),
            ),
            const SizedBox(height: 12),
            Text(
              'Make sure the FastAPI backend is running.',
              style: TextStyle(
                color: Colors.orange[300],
                fontSize: 12,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              final newUrl = backendController.text.trim();
              final prefs = await SharedPreferences.getInstance();
              await prefs.setString('backend_url', newUrl);
              setState(() {
                _backendUrl = newUrl;
              });
              if (mounted) {
                Navigator.pop(context);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Backend URL updated'),
                    backgroundColor: Colors.green,
                  ),
                );
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFF4a9eff),
            ),
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  String _getTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);

    if (difference.inMinutes < 1) {
      return 'just now';
    } else if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h ago';
    } else if (difference.inDays < 7) {
      return '${difference.inDays}d ago';
    } else {
      return '${(difference.inDays / 7).floor()}w ago';
    }
  }
}

// URL Results Page
class URLResultsPage extends StatefulWidget {
  final String url;
  final Map<String, dynamic> result;

  const URLResultsPage({
    super.key,
    required this.url,
    required this.result,
  });

  @override
  State<URLResultsPage> createState() => _URLResultsPageState();
}

class _URLResultsPageState extends State<URLResultsPage> {
  bool _showFlaggedVendors = false;

  @override
  Widget build(BuildContext context) {
    final verdict = widget.result['verdict'] ?? 'Unknown';
    final confidence = (widget.result['confidence'] ?? 0.0) as double;
    final methodUsed = widget.result['method_used'] ?? 'Unknown';
    final details = widget.result['details'] ?? 'No details available';
    final vtResult = widget.result['vt_result'] as Map<String, dynamic>?;
    final mlResult = widget.result['ml_result'] as Map<String, dynamic>?;

    Color verdictColor;
    IconData verdictIcon;

    switch (verdict) {
      case 'Safe':
        verdictColor = Colors.green;
        verdictIcon = Icons.check_circle;
        break;
      case 'Suspicious':
        verdictColor = Colors.orange;
        verdictIcon = Icons.warning;
        break;
      case 'Malicious':
        verdictColor = Colors.red;
        verdictIcon = Icons.dangerous;
        break;
      default:
        verdictColor = Colors.grey;
        verdictIcon = Icons.help;
    }

    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      appBar: AppBar(
        backgroundColor: const Color(0xFF2a3346),
        title: const Text('URL Check Results',
            style: TextStyle(color: Colors.white)),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Verdict Card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: verdictColor.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: verdictColor, width: 2),
                ),
                child: Column(
                  children: [
                    Icon(verdictIcon, color: verdictColor, size: 64),
                    const SizedBox(height: 16),
                    Text(
                      verdict.toUpperCase(),
                      style: TextStyle(
                        color: verdictColor,
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    // Only show confidence for ML Model results
                    if (methodUsed == 'ML Model')
                      Padding(
                        padding: const EdgeInsets.only(bottom: 4),
                        child: Text(
                          'Confidence: ${(confidence * 100).toStringAsFixed(1)}%',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 16,
                          ),
                        ),
                      ),
                    Text(
                      'Method: $methodUsed',
                      style: TextStyle(
                        color: Colors.white.withOpacity(0.7),
                        fontSize: 14,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // URL Display
              _buildSection(
                'Checked URL',
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2a3346),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.link, color: Colors.white70),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          widget.url,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 24),

              // VirusTotal Results (previously "Analysis Details")
              if (vtResult != null) ...[
                _buildSection(
                  'VirusTotal Results',
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF2a3346),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      children: [
                        _buildStatRow(
                            'Malicious',
                            vtResult['malicious']?.toString() ?? '0',
                            Colors.red),
                        _buildStatRow(
                            'Suspicious',
                            vtResult['suspicious']?.toString() ?? '0',
                            Colors.orange),
                        _buildStatRow(
                            'Harmless',
                            vtResult['harmless']?.toString() ?? '0',
                            Colors.green),
                        _buildStatRow(
                            'Undetected',
                            vtResult['undetected']?.toString() ?? '0',
                            Colors.grey),
                        const Divider(color: Colors.white24, height: 24),
                        _buildStatRow(
                            'Detection Rate',
                            vtResult['detection_rate']?.toString() ?? 'N/A',
                            Colors.blue),
                      ],
                    ),
                  ),
                ),

                // Flagged Vendors Section (expandable, only if vendors flagged it)
                if (vtResult['flagged_vendors'] != null &&
                    (vtResult['flagged_vendors'] as List).isNotEmpty) ...[
                  const SizedBox(height: 16),
                  GestureDetector(
                    onTap: () {
                      setState(() {
                        _showFlaggedVendors = !_showFlaggedVendors;
                      });
                    },
                    child: Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: Colors.orange.withOpacity(0.3),
                          width: 1,
                        ),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Row(
                            children: [
                              Icon(
                                Icons.warning_amber_rounded,
                                color: Colors.orange,
                                size: 20,
                              ),
                              const SizedBox(width: 8),
                              Text(
                                'Flagged Vendors (${(vtResult['flagged_vendors'] as List).length})',
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 16,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ],
                          ),
                          Icon(
                            _showFlaggedVendors
                                ? Icons.keyboard_arrow_up
                                : Icons.keyboard_arrow_down,
                            color: Colors.white70,
                          ),
                        ],
                      ),
                    ),
                  ),

                  // Expanded vendor list
                  if (_showFlaggedVendors)
                    Container(
                      margin: const EdgeInsets.only(top: 8),
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'These security vendors flagged this URL:',
                            style: TextStyle(
                              color: Colors.white70,
                              fontSize: 13,
                            ),
                          ),
                          const SizedBox(height: 12),
                          ...(vtResult['flagged_vendors'] as List)
                              .map((vendor) {
                            final vendorName = vendor['vendor'] ?? 'Unknown';
                            final category = vendor['category'] ?? 'malicious';
                            final categoryColor = category == 'malicious'
                                ? Colors.red
                                : Colors.orange;

                            return Padding(
                              padding: const EdgeInsets.symmetric(vertical: 6),
                              child: Row(
                                children: [
                                  Icon(
                                    category == 'malicious'
                                        ? Icons.dangerous
                                        : Icons.warning,
                                    color: categoryColor,
                                    size: 16,
                                  ),
                                  const SizedBox(width: 8),
                                  Expanded(
                                    child: Text(
                                      vendorName,
                                      style: const TextStyle(
                                        color: Colors.white,
                                        fontSize: 14,
                                      ),
                                    ),
                                  ),
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 8,
                                      vertical: 2,
                                    ),
                                    decoration: BoxDecoration(
                                      color: categoryColor.withOpacity(0.2),
                                      borderRadius: BorderRadius.circular(4),
                                      border: Border.all(
                                        color: categoryColor.withOpacity(0.5),
                                        width: 1,
                                      ),
                                    ),
                                    child: Text(
                                      category,
                                      style: TextStyle(
                                        color: categoryColor,
                                        fontSize: 11,
                                        fontWeight: FontWeight.bold,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            );
                          }).toList(),
                        ],
                      ),
                    ),
                ],
                const SizedBox(height: 24),
              ],

              // Analysis Details (previously "VirusTotal Results")
              _buildSection(
                'Analysis Details',
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFF2a3346),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    details,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 14,
                      height: 1.5,
                    ),
                  ),
                ),
              ),

              // ML Model Results
              if (mlResult != null) ...[
                const SizedBox(height: 24),
                _buildSection(
                  'ML Model Results',
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: const Color(0xFF2a3346),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      children: [
                        _buildStatRow(
                          'Prediction',
                          mlResult['prediction']?.toString() ?? 'Unknown',
                          mlResult['prediction'] == 'Malicious'
                              ? Colors.red
                              : Colors.green,
                        ),
                        _buildStatRow(
                          'Malicious Probability',
                          '${((mlResult['malicious_probability'] ?? 0.0) * 100).toStringAsFixed(2)}%',
                          Colors.red,
                        ),
                        _buildStatRow(
                          'Benign Probability',
                          '${((mlResult['benign_probability'] ?? 0.0) * 100).toStringAsFixed(2)}%',
                          Colors.green,
                        ),
                        _buildStatRow(
                          'Model Confidence',
                          '${((mlResult['confidence'] ?? 0.0) * 100).toStringAsFixed(2)}%',
                          Colors.blue,
                        ),
                      ],
                    ),
                  ),
                ),
              ],

              const SizedBox(height: 32),

              // Action Button
              SizedBox(
                width: double.infinity,
                height: 50,
                child: ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context);
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4a9eff),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                  ),
                  child: const Text(
                    'Check Another URL',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSection(String title, Widget content) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 18,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 12),
        content,
      ],
    );
  }

  Widget _buildStatRow(String label, String value, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              color: Colors.white.withOpacity(0.7),
              fontSize: 14,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              color: color,
              fontSize: 14,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}

class ScanAttachmentPage extends StatefulWidget {
  final File? sharedFile;
  final Function(bool isSafe)? onScanComplete;

  const ScanAttachmentPage({super.key, this.sharedFile, this.onScanComplete});

  @override
  State<ScanAttachmentPage> createState() => _ScanAttachmentPageState();
}

class _ScanAttachmentPageState extends State<ScanAttachmentPage>
    with SingleTickerProviderStateMixin {
  bool _isScanning = false;
  late TabController _tabController;
  final TextEditingController _hashController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);

    // Auto-scan shared file if provided
    if (widget.sharedFile != null) {
      Future.delayed(const Duration(milliseconds: 300), () {
        _scanSharedFile(widget.sharedFile!);
      });
    }
  }

  Future<void> _scanSharedFile(File file) async {
    setState(() {
      _isScanning = true;
    });

    try {
      if (!await file.exists()) {
        throw Exception('File not found');
      }

      String fileName = file.path.split('/').last;

      // Calculate SHA256
      var bytes = await file.readAsBytes();
      var hash = sha256.convert(bytes);
      String sha256Hash = hash.toString();

      // Get VirusTotal results
      await _scanWithVirusTotal(sha256Hash, fileName);
    } catch (e) {
      setState(() {
        _isScanning = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: ${e.toString()}'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 4),
          ),
        );
      }
    }
  }

  @override
  void dispose() {
    _tabController.dispose();
    _hashController.dispose();
    super.dispose();
  }

  Future<void> _pickAndScanFile() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.any,
        allowMultiple: false,
      );

      if (result != null && result.files.isNotEmpty) {
        final pickedFile = result.files.first;

        if (pickedFile.path == null) {
          throw Exception('Could not access file path');
        }

        setState(() {
          _isScanning = true;
        });

        File file = File(pickedFile.path!);
        String fileName = pickedFile.name;

        // Calculate SHA256
        var bytes = await file.readAsBytes();
        var hash = sha256.convert(bytes);
        String sha256Hash = hash.toString();

        // Get VirusTotal results
        await _scanWithVirusTotal(sha256Hash, fileName);
      }
    } catch (e) {
      setState(() {
        _isScanning = false;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error: ${e.toString()}'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 4),
          ),
        );
      }
    }
  }

  Future<void> _scanHash() async {
    final hash = _hashController.text.trim();

    if (hash.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Please enter a file hash'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }

    // Validate hash format (MD5=32, SHA1=40, SHA256=64 characters of hex)
    if (!RegExp(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
        .hasMatch(hash)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
              'Invalid hash format. Please enter a valid MD5, SHA1, or SHA256 hash.'),
          backgroundColor: Colors.red,
          duration: Duration(seconds: 4),
        ),
      );
      return;
    }

    setState(() {
      _isScanning = true;
    });

    try {
      // Check if we have a cached result for this hash (within 8 hours)
      final cachedResult =
          await HistoryManager.getCachedFileResult(hash, 'Hash');

      if (cachedResult != null) {
        setState(() {
          _isScanning = false;
        });

        print('[CACHE] Using cached result for hash $hash');

        // Show cached result notification
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  Icon(Icons.history, color: Colors.white),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Showing cached result (scanned ${_getTimeAgo(cachedResult.timestamp)})',
                    ),
                  ),
                ],
              ),
              backgroundColor: Colors.blue,
              duration: const Duration(seconds: 3),
            ),
          );

          // Navigate to cached results page
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: 'Hash: ${hash.substring(0, 16)}...',
                sha256: hash,
                vtData: cachedResult.fullData ?? {},
                isNotFound: cachedResult.verdict.toLowerCase() == 'unknown',
              ),
            ),
          );
        }
        return; // Don't make API call
      }
      // Get API key from shared preferences
      final prefs = await SharedPreferences.getInstance();
      final apiKey = prefs.getString('virustotal_api_key');

      if (apiKey == null || apiKey.isEmpty) {
        setState(() {
          _isScanning = false;
        });

        if (mounted) {
          showDialog(
            context: context,
            builder: (context) => AlertDialog(
              backgroundColor: const Color(0xFF2a3346),
              title: const Text(
                'API Key Required',
                style: TextStyle(color: Colors.white),
              ),
              content: const Text(
                'Please add your VirusTotal API key in Settings to scan hashes.',
                style: TextStyle(color: Colors.white70),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context);
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (context) => const SettingsPage(),
                      ),
                    );
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4a9eff),
                  ),
                  child: const Text('Go to Settings'),
                ),
              ],
            ),
          );
        }
        return;
      }

      // Make real API call to VirusTotal
      final response = await http.get(
        Uri.parse('https://www.virustotal.com/api/v3/files/$hash'),
        headers: {
          'x-apikey': apiKey,
        },
      );

      setState(() {
        _isScanning = false;
      });

      if (response.statusCode == 200) {
        // Success - hash found in VT database
        final dynamic decodedData = json.decode(response.body);
        final Map<String, dynamic> data =
            Map<String, dynamic>.from(decodedData as Map);

        // Extract stats for history
        int malicious = 0;
        int suspicious = 0;
        int totalEngines = 0;
        String verdict = 'Unknown';

        try {
          final attributes =
              data['data']?['attributes'] as Map<String, dynamic>?;
          if (attributes != null) {
            final stats =
                attributes['last_analysis_stats'] as Map<String, dynamic>?;
            if (stats != null) {
              malicious = (stats['malicious'] as int?) ?? 0;
              suspicious = (stats['suspicious'] as int?) ?? 0;
              int undetected = (stats['undetected'] as int?) ?? 0;
              int harmless = (stats['harmless'] as int?) ?? 0;
              totalEngines = malicious + suspicious + undetected + harmless;

              verdict =
                  (malicious > 0 || suspicious > 0) ? 'Malicious' : 'Safe';
            }
          }
        } catch (e) {
          print('Error parsing stats: $e');
        }

        // Save to history
        final historyItem = HistoryItem(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'Hash',
          name: hash,
          verdict: verdict,
          detectionStats: '$malicious/$totalEngines vendors flagged',
          timestamp: DateTime.now(),
          fullData: data,
        );
        await HistoryManager.saveHistoryItem(historyItem);

        if (mounted) {
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: 'Hash: ${hash.substring(0, 16)}...',
                sha256: hash,
                vtData: data,
              ),
            ),
          );
        }
      } else if (response.statusCode == 404) {
        // Hash not found in VT database
        final notFoundData = {
          'data': {
            'attributes': {
              'last_analysis_stats': {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'harmless': 0,
              },
              'last_analysis_results': {},
            }
          }
        };

        // Save to history
        final historyItem = HistoryItem(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'Hash',
          name: hash,
          verdict: 'Unknown',
          detectionStats: 'Not found in database',
          timestamp: DateTime.now(),
          fullData: notFoundData,
        );
        await HistoryManager.saveHistoryItem(historyItem);

        if (mounted) {
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: 'Hash: ${hash.substring(0, 16)}...',
                sha256: hash,
                vtData: notFoundData,
                isNotFound: true,
              ),
            ),
          );
        }
      } else if (response.statusCode == 401) {
        // Invalid API key
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                  'Invalid API key. Please check your VirusTotal API key in Settings.'),
              backgroundColor: Colors.red,
              duration: Duration(seconds: 5),
            ),
          );
        }
      } else {
        // Other error
        throw Exception('VirusTotal API error: ${response.statusCode}');
      }
    } catch (e) {
      setState(() {
        _isScanning = false;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error scanning hash: ${e.toString()}'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 5),
          ),
        );
      }
    }
  }

  Future<void> _scanWithVirusTotal(String sha256Hash, String fileName) async {
    try {
      // Check if we have a cached result for this hash (within 8 hours)
      final cachedResult =
          await HistoryManager.getCachedFileResult(sha256Hash, 'File');

      if (cachedResult != null) {
        setState(() {
          _isScanning = false;
        });

        print(
            '[CACHE] Using cached result for file $fileName (hash: ${sha256Hash.substring(0, 16)}...)');

        // Show cached result notification
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  Icon(Icons.history, color: Colors.white),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Showing cached result (scanned ${_getTimeAgo(cachedResult.timestamp)})',
                    ),
                  ),
                ],
              ),
              backgroundColor: Colors.blue,
              duration: const Duration(seconds: 3),
            ),
          );

          // Call completion callback if provided
          if (widget.onScanComplete != null) {
            final isSafe = cachedResult.verdict.toLowerCase() == 'safe';
            widget.onScanComplete!(isSafe);
          }

          // Navigate to cached results page
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: fileName,
                sha256: sha256Hash,
                vtData: cachedResult.fullData ?? {},
                isNotFound: cachedResult.verdict.toLowerCase() == 'unknown',
              ),
            ),
          );
        }
        return; // Don't make API call
      }
      // Get API key from shared preferences
      final prefs = await SharedPreferences.getInstance();
      final apiKey = prefs.getString('virustotal_api_key');

      if (apiKey == null || apiKey.isEmpty) {
        setState(() {
          _isScanning = false;
        });

        if (mounted) {
          showDialog(
            context: context,
            builder: (context) => AlertDialog(
              backgroundColor: const Color(0xFF2a3346),
              title: const Text(
                'API Key Required',
                style: TextStyle(color: Colors.white),
              ),
              content: const Text(
                'Please add your VirusTotal API key in Settings to scan files.',
                style: TextStyle(color: Colors.white70),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  onPressed: () {
                    Navigator.pop(context);
                    Navigator.push(
                      context,
                      MaterialPageRoute(
                        builder: (context) => const SettingsPage(),
                      ),
                    );
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF4a9eff),
                  ),
                  child: const Text('Go to Settings'),
                ),
              ],
            ),
          );
        }
        return;
      }

      // Make real API call to VirusTotal
      final response = await http.get(
        Uri.parse('https://www.virustotal.com/api/v3/files/$sha256Hash'),
        headers: {
          'x-apikey': apiKey,
        },
      );

      setState(() {
        _isScanning = false;
      });

      if (response.statusCode == 200) {
        // Success - file found in VT database
        final dynamic decodedData = json.decode(response.body);
        final Map<String, dynamic> data =
            Map<String, dynamic>.from(decodedData as Map);

        // Extract stats for history
        int malicious = 0;
        int suspicious = 0;
        int totalEngines = 0;
        String verdict = 'Unknown';

        try {
          final attributes =
              data['data']?['attributes'] as Map<String, dynamic>?;
          if (attributes != null) {
            final stats =
                attributes['last_analysis_stats'] as Map<String, dynamic>?;
            if (stats != null) {
              malicious = (stats['malicious'] as int?) ?? 0;
              suspicious = (stats['suspicious'] as int?) ?? 0;
              int undetected = (stats['undetected'] as int?) ?? 0;
              int harmless = (stats['harmless'] as int?) ?? 0;
              totalEngines = malicious + suspicious + undetected + harmless;

              verdict =
                  (malicious > 0 || suspicious > 0) ? 'Malicious' : 'Safe';
            }
          }
        } catch (e) {
          print('Error parsing stats: $e');
        }

        // Save to history
        final historyItem = HistoryItem(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'File',
          name: sha256Hash, // Use hash as name for cache lookup
          verdict: verdict,
          detectionStats: '$malicious/$totalEngines vendors flagged',
          timestamp: DateTime.now(),
          fullData: {
            ...data,
            'display_name': fileName
          }, // Store display name separately
        );
        await HistoryManager.saveHistoryItem(historyItem);

        // Call completion callback if provided
        if (widget.onScanComplete != null) {
          final isSafe = malicious == 0 && suspicious == 0;
          widget.onScanComplete!(isSafe);
        }

        if (mounted) {
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: fileName,
                sha256: sha256Hash,
                vtData: data,
              ),
            ),
          );
        }
      } else if (response.statusCode == 404) {
        // File not found in VT database
        final notFoundData = {
          'data': {
            'attributes': {
              'last_analysis_stats': {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 0,
                'harmless': 0,
              },
              'last_analysis_results': {},
            }
          }
        };

        // Save to history
        final historyItem = HistoryItem(
          id: DateTime.now().millisecondsSinceEpoch.toString(),
          type: 'File',
          name: sha256Hash, // Use hash as name for cache lookup
          verdict: 'Unknown',
          detectionStats: 'Not found in database',
          timestamp: DateTime.now(),
          fullData: {
            ...notFoundData,
            'display_name': fileName
          }, // Store display name separately
        );
        await HistoryManager.saveHistoryItem(historyItem);

        if (mounted) {
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(
              builder: (context) => ScanResultsPage(
                fileName: fileName,
                sha256: sha256Hash,
                vtData: notFoundData,
                isNotFound: true,
              ),
            ),
          );
        }
      } else if (response.statusCode == 401) {
        // Invalid API key
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                  'Invalid API key. Please check your VirusTotal API key in Settings.'),
              backgroundColor: Colors.red,
              duration: Duration(seconds: 5),
            ),
          );
        }
      } else {
        // Other error
        throw Exception(
            'VirusTotal API error: ${response.statusCode} - ${response.body}');
      }
    } catch (e) {
      setState(() {
        _isScanning = false;
      });

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error scanning file: ${e.toString()}'),
            backgroundColor: Colors.red,
            duration: const Duration(seconds: 5),
          ),
        );
      }
    }
  }

  String _getTimeAgo(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);

    if (difference.inMinutes < 1) {
      return 'just now';
    } else if (difference.inMinutes < 60) {
      return '${difference.inMinutes}m ago';
    } else if (difference.inHours < 24) {
      return '${difference.inHours}h ago';
    } else if (difference.inDays < 7) {
      return '${difference.inDays}d ago';
    } else {
      return '${(difference.inDays / 7).floor()}w ago';
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Padding(
              padding: const EdgeInsets.all(24.0),
              child: Row(
                children: [
                  IconButton(
                    icon: const Icon(
                      Icons.arrow_back,
                      color: Colors.white,
                      size: 28,
                    ),
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                  const SizedBox(width: 16),
                  const Expanded(
                    child: Text(
                      'Scan Attachment',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 24,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            // Tabs
            Container(
              margin: const EdgeInsets.symmetric(horizontal: 24),
              decoration: BoxDecoration(
                color: const Color(0xFF2a3346),
                borderRadius: BorderRadius.circular(8),
              ),
              child: TabBar(
                controller: _tabController,
                indicator: BoxDecoration(
                  color: const Color(0xFF4a9eff),
                  borderRadius: BorderRadius.circular(8),
                ),
                labelColor: Colors.white,
                unselectedLabelColor: Colors.white70,
                indicatorSize: TabBarIndicatorSize.tab,
                dividerColor: Colors.transparent,
                tabs: const [
                  Tab(
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.folder_open, size: 18),
                        SizedBox(width: 8),
                        Text('Upload File'),
                      ],
                    ),
                  ),
                  Tab(
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.tag, size: 18),
                        SizedBox(width: 8),
                        Text('Enter Hash'),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            // Tab Content
            Expanded(
              child: TabBarView(
                controller: _tabController,
                children: [
                  // File Upload Tab
                  _buildFileUploadTab(),
                  // Hash Input Tab
                  _buildHashInputTab(),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFileUploadTab() {
    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Center(
        child: SingleChildScrollView(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // File Icon
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.05),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.insert_drive_file,
                  color: Colors.white,
                  size: 60,
                ),
              ),
              const SizedBox(height: 32),
              const Text(
                'Select file to scan',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 22,
                  fontWeight: FontWeight.w600,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              const Text(
                'We will check it against malware databases',
                style: TextStyle(
                  color: Colors.white70,
                  fontSize: 14,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 40),
              // Choose File Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _isScanning ? null : _pickAndScanFile,
                  icon: _isScanning
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(
                          Icons.folder_open,
                          color: Colors.white,
                          size: 20,
                        ),
                  label: Text(
                    _isScanning ? 'Scanning...' : 'Choose File',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF5a7c9e),
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHashInputTab() {
    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Center(
        child: SingleChildScrollView(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Hash Icon
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.05),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.fingerprint,
                  color: Colors.white,
                  size: 60,
                ),
              ),
              const SizedBox(height: 32),
              const Text(
                'Enter file hash',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 22,
                  fontWeight: FontWeight.w600,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              const Text(
                'Supports MD5, SHA1, and SHA256 hashes',
                style: TextStyle(
                  color: Colors.white70,
                  fontSize: 14,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 40),
              // Hash Input Field
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0xFF2a3346),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: Colors.white24,
                    width: 1,
                  ),
                ),
                child: TextField(
                  controller: _hashController,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 14,
                    fontFamily: 'monospace',
                  ),
                  decoration: const InputDecoration(
                    hintText: 'e.g., a1b2c3d4e5f6...',
                    hintStyle: TextStyle(
                      color: Colors.white38,
                      fontFamily: 'monospace',
                    ),
                    border: InputBorder.none,
                    icon: Icon(
                      Icons.tag,
                      color: Colors.white54,
                    ),
                  ),
                  maxLines: 3,
                  minLines: 1,
                  enabled: !_isScanning,
                ),
              ),
              const SizedBox(height: 24),
              // Info box
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.blue.withOpacity(0.1),
                  border: Border.all(
                    color: Colors.blue.withOpacity(0.3),
                    width: 1,
                  ),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.info_outline,
                      color: Colors.blue[300],
                      size: 20,
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Paste the MD5, SHA1, or SHA256 hash of the file you want to check',
                        style: TextStyle(
                          color: Colors.blue[200],
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),
              // Scan Button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _isScanning ? null : _scanHash,
                  icon: _isScanning
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : const Icon(
                          Icons.search,
                          color: Colors.white,
                          size: 20,
                        ),
                  label: Text(
                    _isScanning ? 'Scanning...' : 'Scan Hash',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF5a7c9e),
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class ScanResultsPage extends StatelessWidget {
  final String fileName;
  final String sha256;
  final Map<String, dynamic>? vtData;
  final bool isNotFound;

  const ScanResultsPage({
    super.key,
    required this.fileName,
    required this.sha256,
    this.vtData,
    this.isNotFound = false,
  });

  @override
  Widget build(BuildContext context) {
    int malicious = 0;
    int suspicious = 0;
    int undetected = 0;
    int harmless = 0;
    Map<String, dynamic> scanResults = {};

    if (vtData != null &&
        vtData!['data'] != null &&
        vtData!['data']['attributes'] != null) {
      try {
        final data = vtData!['data'] as Map<String, dynamic>?;
        final attributes = data?['attributes'] as Map<String, dynamic>?;

        if (attributes != null) {
          final stats =
              attributes['last_analysis_stats'] as Map<String, dynamic>?;
          if (stats != null) {
            malicious = (stats['malicious'] as int?) ?? 0;
            suspicious = (stats['suspicious'] as int?) ?? 0;
            undetected = (stats['undetected'] as int?) ?? 0;
            harmless = (stats['harmless'] as int?) ?? 0;
          }

          final results = attributes['last_analysis_results'];
          if (results != null) {
            scanResults = Map<String, dynamic>.from(results as Map);
          }
        }
      } catch (e) {
        // Handle parsing errors gracefully
        print('Error parsing VT data: $e');
      }
    }

    bool isSafe = malicious == 0 && suspicious == 0;
    int totalEngines = malicious + suspicious + undetected + harmless;

    // Handle not found case
    String headerTitle;
    String headerSubtitle;
    Color headerColor;

    if (isNotFound) {
      headerTitle = 'File Not Found';
      headerSubtitle = 'No data available in VirusTotal';
      headerColor = Colors.orange;
    } else if (isSafe) {
      headerTitle = 'File is Safe';
      headerSubtitle = 'No threats detected';
      headerColor = Colors.green;
    } else {
      headerTitle = 'File is Malicious';
      headerSubtitle = 'Threats detected - DO NOT open';
      headerColor = Colors.red;
    }

    return Scaffold(
      backgroundColor: const Color(0xFF1a1d2e),
      body: SafeArea(
        child: Column(
          children: [
            // Header
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: headerColor,
              ),
              child: Row(
                children: [
                  IconButton(
                    icon: const Icon(
                      Icons.arrow_back,
                      color: Colors.white,
                      size: 28,
                    ),
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          headerTitle,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          headerSubtitle,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                          ),
                        ),
                      ],
                    ),
                  ),
                  Icon(
                    isSafe ? Icons.check_circle : Icons.dangerous,
                    color: Colors.white,
                    size: 40,
                  ),
                ],
              ),
            ),
            // Content
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // File Info Card
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: const Color(0xFF2a3346),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'File Information',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Row(
                            children: [
                              const Icon(
                                Icons.insert_drive_file,
                                color: Colors.white70,
                                size: 20,
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Text(
                                      'File Name',
                                      style: TextStyle(
                                        color: Colors.white54,
                                        fontSize: 12,
                                      ),
                                    ),
                                    const SizedBox(height: 4),
                                    Text(
                                      fileName,
                                      style: const TextStyle(
                                        color: Colors.white,
                                        fontSize: 14,
                                        fontWeight: FontWeight.w500,
                                      ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          const Divider(
                            color: Colors.white24,
                            height: 32,
                          ),
                          Row(
                            children: [
                              const Icon(
                                Icons.fingerprint,
                                color: Colors.white70,
                                size: 20,
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    const Text(
                                      'SHA-256',
                                      style: TextStyle(
                                        color: Colors.white54,
                                        fontSize: 12,
                                      ),
                                    ),
                                    const SizedBox(height: 4),
                                    Text(
                                      sha256,
                                      style: const TextStyle(
                                        color: Colors.white,
                                        fontSize: 12,
                                        fontFamily: 'monospace',
                                      ),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),
                    // Scan Results Card
                    if (!isNotFound) ...[
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(20),
                        decoration: BoxDecoration(
                          color: const Color(0xFF2a3346),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Security Scan Results',
                              style: TextStyle(
                                color: Colors.white,
                                fontSize: 18,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 16),
                            Row(
                              children: [
                                const Icon(
                                  Icons.shield,
                                  color: Colors.white70,
                                  size: 20,
                                ),
                                const SizedBox(width: 12),
                                Text(
                                  'Scanned by $totalEngines security vendors',
                                  style: const TextStyle(
                                    color: Colors.white70,
                                    fontSize: 14,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 20),
                            _buildStatRow(
                              'Malicious',
                              malicious,
                              Colors.red,
                            ),
                            const SizedBox(height: 12),
                            _buildStatRow(
                              'Suspicious',
                              suspicious,
                              Colors.orange,
                            ),
                            const SizedBox(height: 12),
                            _buildStatRow(
                              'Clean',
                              undetected + harmless,
                              Colors.green,
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 24),
                    ],
                    // Recommendation Card
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        color: isNotFound
                            ? Colors.orange.withOpacity(0.1)
                            : (isSafe
                                ? Colors.green.withOpacity(0.1)
                                : Colors.red.withOpacity(0.1)),
                        border: Border.all(
                          color: isNotFound
                              ? Colors.orange
                              : (isSafe ? Colors.green : Colors.red),
                          width: 2,
                        ),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Icon(
                                isNotFound
                                    ? Icons.info_outline
                                    : (isSafe
                                        ? Icons.check_circle_outline
                                        : Icons.warning_amber_rounded),
                                color: isNotFound
                                    ? Colors.orange
                                    : (isSafe ? Colors.green : Colors.red),
                                size: 28,
                              ),
                              const SizedBox(width: 12),
                              Text(
                                'Recommendation',
                                style: TextStyle(
                                  color: isNotFound
                                      ? Colors.orange
                                      : (isSafe ? Colors.green : Colors.red),
                                  fontSize: 18,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          Text(
                            isNotFound
                                ? 'This file is not in VirusTotal\'s database. This could mean it\'s a new file or hasn\'t been scanned before. Exercise caution and only open files from trusted sources.'
                                : (isSafe
                                    ? 'This file appears to be safe. No security vendors have flagged it as malicious. You can proceed to open or download it.'
                                    : 'Warning! This file has been flagged as malicious by $malicious security vendor(s). DO NOT open or execute this file. Delete it immediately to protect your device.'),
                            style: TextStyle(
                              color: isNotFound
                                  ? Colors.orange
                                  : (isSafe ? Colors.green : Colors.red),
                              fontSize: 14,
                              height: 1.5,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (malicious > 0 || suspicious > 0) ...[
                      const SizedBox(height: 24),
                      const Text(
                        'Flagged by Vendors',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 12),
                      ...scanResults.entries.where((entry) {
                        try {
                          final value = entry.value as Map<String, dynamic>?;
                          final category = value?['category'] as String?;
                          return category == 'malicious' ||
                              category == 'suspicious';
                        } catch (e) {
                          return false;
                        }
                      }).map((entry) {
                        final value = entry.value as Map<String, dynamic>;
                        final category =
                            value['category'] as String? ?? 'unknown';
                        final result = value['result'] as String? ?? 'Detected';

                        return Container(
                          margin: const EdgeInsets.only(bottom: 8),
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: const Color(0xFF2a3346),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Row(
                            children: [
                              Icon(
                                Icons.error_outline,
                                color: category == 'malicious'
                                    ? Colors.red
                                    : Colors.orange,
                                size: 20,
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Text(
                                  entry.key,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 14,
                                  ),
                                ),
                              ),
                              Text(
                                result,
                                style: TextStyle(
                                  color: category == 'malicious'
                                      ? Colors.red
                                      : Colors.orange,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ],
                          ),
                        );
                      }).toList(),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatRow(String label, int count, Color color) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Row(
          children: [
            Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                color: color,
                shape: BoxShape.circle,
              ),
            ),
            const SizedBox(width: 12),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 14,
              ),
            ),
          ],
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          decoration: BoxDecoration(
            color: color.withOpacity(0.2),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Text(
            count.toString(),
            style: TextStyle(
              color: color,
              fontSize: 14,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ],
    );
  }
}
