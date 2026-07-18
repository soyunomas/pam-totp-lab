from pathlib import Path

path = Path("TODO_AUTHENTICATION_IDEAS.md")
text = path.read_text(encoding="utf-8")

heading = "## 11. `pam_schedule_totp_override`: excepción horaria autorizada por profesor\n"
status = (
    "\n> **Estado:** implementado en `pam_schedule_totp_override/`, con pruebas "
    "de política, archivos, concurrencia, integración PAM y endurecimiento.\n"
)
if status.strip() not in text:
    if heading not in text:
        raise SystemExit("schedule override heading not found")
    text = text.replace(heading, heading + status, 1)

for number in range(1, 13):
    pending = f"- [ ] `SCHEDOVR-{number:02d}`"
    complete = f"- [x] `SCHEDOVR-{number:02d}`"
    if pending in text:
        text = text.replace(pending, complete, 1)
    elif complete not in text:
        raise SystemExit(f"missing TODO item SCHEDOVR-{number:02d}")

acceptance = [
    "A puede entrar por la mañana sin TOTP de excepción.",
    "B no puede entrar por la mañana usando solo la contraseña compartida.",
    "B puede entrar por la mañana con el TOTP específico de B.",
    "El TOTP de A no autoriza a B ni a C.",
    "Un TOTP aceptado no puede reutilizarse en otro intento o servicio.",
    "Un secreto ausente, corrupto o con permisos inseguros produce denegación.",
    "Una configuración horaria solapada, incompleta o inválida produce denegación.",
    "Los intentos concurrentes no aceptan dos veces el mismo contador.",
    "Los logs permiten auditar la excepción sin revelar el código.",
    "Cambiar la hora del cliente no altera la decisión del servidor.",
]
for item in acceptance:
    pending = f"- [ ] {item}"
    complete = f"- [x] {item}"
    if pending in text:
        text = text.replace(pending, complete, 1)
    elif complete not in text:
        raise SystemExit(f"missing acceptance item: {item}")

path.write_text(text, encoding="utf-8")
