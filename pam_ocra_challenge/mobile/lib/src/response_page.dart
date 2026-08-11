import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'ocra.dart';
import 'profile.dart';

class ResponsePage extends StatefulWidget {
  const ResponsePage({required this.profile, super.key});

  final OcraProfile profile;

  @override
  State<ResponsePage> createState() => _ResponsePageState();
}

class _ResponsePageState extends State<ResponsePage> {
  final _controller = TextEditingController();
  Timer? _clearTimer;
  String? _response;
  String? _error;

  void _compute() {
    final challenge = _controller.text;
    if (!RegExp(r'^\d{10}$').hasMatch(challenge)) {
      setState(() {
        _error = 'Introduce exactamente 10 dígitos';
        _response = null;
      });
      return;
    }
    final response = computeOcraResponse(
      decodeBase32Secret(widget.profile.secret),
      challenge,
    );
    _clearTimer?.cancel();
    setState(() {
      _error = null;
      _response = response;
    });
    _clearTimer = Timer(const Duration(seconds: 30), () {
      if (mounted) setState(() => _response = null);
    });
  }

  @override
  void dispose() {
    _clearTimer?.cancel();
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.profile.identity)),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          TextField(
            key: const Key('challenge'),
            controller: _controller,
            autofocus: true,
            keyboardType: TextInputType.number,
            maxLength: 10,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            decoration: InputDecoration(
              labelText: 'Desafío OCRA',
              hintText: '0000000000',
              errorText: _error,
              border: const OutlineInputBorder(),
            ),
            onSubmitted: (_) => _compute(),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: _compute,
            child: const Text('Calcular respuesta'),
          ),
          const SizedBox(height: 32),
          if (_response case final response?)
            Semantics(
              label: 'Respuesta OCRA de ocho dígitos',
              child: Column(
                children: [
                  Text(
                    'Respuesta',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  SelectableText(
                    response,
                    key: const Key('response'),
                    style: Theme.of(context).textTheme.displayMedium?.copyWith(
                      fontFeatures: const [FontFeature.tabularFigures()],
                    ),
                  ),
                  TextButton(
                    onPressed: () {
                      _clearTimer?.cancel();
                      setState(() => _response = null);
                    },
                    child: const Text('Ocultar'),
                  ),
                  const Text('Se ocultará automáticamente en 30 segundos.'),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
