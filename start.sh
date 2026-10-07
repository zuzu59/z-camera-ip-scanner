#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP="$ROOT_DIR/scan_camera.py"
PID_FILE="$ROOT_DIR/.scan_camera.pid"
LOG_FILE="$ROOT_DIR/scan_camera.log"
PYTHON="$ROOT_DIR/.venv/bin/python"

is_running() {
  local pid="$1" command
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || return 1
  command="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [[ "$command" == *"$APP"* ]]
}

read_pid() {
  [[ -f "$PID_FILE" ]] && tr -d '[:space:]' < "$PID_FILE"
}

print_access_url() {
  local host="${SCAN_CAMERA_HOST:-0.0.0.0}"
  if [[ "$host" == "0.0.0.0" || "$host" == "::" ]]; then
    host="$("$PYTHON" -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("192.0.2.1", 80)); print(s.getsockname()[0]); s.close()' 2>/dev/null || true)"
    if [[ -z "$host" || "$host" == "0.0.0.0" ]]; then
      host="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    if [[ -z "$host" ]]; then
      host="127.0.0.1"
      echo "Impossible de détecter l’adresse IP réseau; URL locale uniquement."
    fi
  fi
  echo "URL : http://$host:8092/"
}

start() {
  if [[ ! -f "$APP" ]]; then
    echo "Erreur : scanner introuvable : $APP" >&2
    exit 1
  fi

  local system_python
  system_python="$(command -v python3 || true)"
  if [[ -z "$system_python" ]]; then
    echo "Erreur : python3 est introuvable. Installez Python 3 sans sudo, puis relancez." >&2
    exit 1
  fi

  if [[ ! -x "$PYTHON" ]]; then
    echo "Création de l’environnement Python local (.venv)…"
    if ! "$system_python" -m venv "$ROOT_DIR/.venv"; then
      echo "Impossible de créer .venv. Vérifiez que le module venv est disponible pour Python 3 (aucun sudo n’est nécessaire)." >&2
      exit 1
    fi
  fi

  echo "Vérification/installation des dépendances dans .venv…"
  if ! "$PYTHON" -m pip install -r "$ROOT_DIR/requirements.txt"; then
    echo "Échec de l’installation des dépendances. Vérifiez votre connexion et requirements.txt." >&2
    exit 1
  fi

  local pid
  pid="$(read_pid || true)"
  if [[ -n "$pid" ]] && is_running "$pid"; then
    echo "Le scanner est déjà démarré (PID $pid)."
    print_access_url
    return
  fi

  nohup "$PYTHON" "$APP" >> "$LOG_FILE" 2>&1 < /dev/null &
  pid=$!
  echo "$pid" > "$PID_FILE"
  sleep 1
  if is_running "$pid"; then
    echo "Scanner démarré (PID $pid)."
    print_access_url
    echo "Logs : $LOG_FILE"
  else
    rm -f "$PID_FILE"
    echo "Échec du démarrage. Consultez les logs : $LOG_FILE" >&2
    exit 1
  fi
}

status() {
  local pid
  pid="$(read_pid || true)"
  if [[ -n "$pid" ]] && is_running "$pid"; then
    echo "Scanner en cours d’exécution (PID $pid)."
    print_access_url
    return 0
  fi
  rm -f "$PID_FILE"
  echo "Scanner arrêté."
  return 1
}

stop() {
  local pid i
  pid="$(read_pid || true)"
  if [[ -z "$pid" ]] || ! is_running "$pid"; then
    rm -f "$PID_FILE"
    echo "Le scanner est déjà arrêté."
    return 0
  fi

  kill "$pid"
  for i in {1..10}; do
    if ! is_running "$pid"; then
      rm -f "$PID_FILE"
      echo "Scanner arrêté."
      return 0
    fi
    sleep 1
  done

  kill -9 "$pid" 2>/dev/null || true
  for i in {1..5}; do
    if ! is_running "$pid"; then
      break
    fi
    sleep 1
  done
  rm -f "$PID_FILE"
  echo "Scanner arrêté de force (PID $pid)."
}

show_help() {
  cat <<EOF
Usage : $0 [commande]

Commandes disponibles :
  start       Démarre le scanner en arrière-plan (commande par défaut).
              Crée .venv et installe les dépendances depuis requirements.txt
              si nécessaire, sans sudo. Affiche ensuite l’URL d’accès.
  status      Indique si le scanner est actif et affiche son URL.
  stop        Arrête le scanner.
  restart     Arrête puis redémarre le scanner.
  -h, --help  Affiche cette aide détaillée.

Exemples :
  $0             # démarre le scanner
  $0 start       # démarre explicitement le scanner
  $0 status      # vérifie son état et affiche l’URL
  $0 restart     # redémarre le scanner
  $0 stop        # arrête le scanner
  $0 --help      # affiche cette aide

Le serveur écoute par défaut sur toutes les interfaces, port 8092.
L’adresse IP locale est détectée automatiquement pour afficher l’URL.
Les logs sont enregistrés dans scan_camera.log.
EOF
}

case "${1:-start}" in
  start)  start ;;
  status) status ;;
  stop)   stop ;;
  restart)
    stop
    start
    ;;
  -h|--help|help) show_help ;;
  *)
    echo "Erreur : commande inconnue : $1" >&2
    echo >&2
    show_help >&2
    exit 2
    ;;
esac
