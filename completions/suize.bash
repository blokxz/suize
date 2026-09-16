# Completado de bash para Suize.
#
# Instalación: copiar este archivo a /etc/bash_completion.d/suize, o cargarlo
# desde ~/.bashrc con:
#
#     source /ruta/a/suize/completions/suize.bash
#
# Ver la sección "Autocompletado" del README.
#
# Si añades o quitas opciones en src/suize/cli.py, actualiza también este
# archivo: tests/unit/test_completions.py comprueba que no se separen.

_suize_units() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1}'
}

_suize() {
    local cur prev subcommand index
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    # Opciones válidas antes y después del subcomando.
    local global_opts="--config --no-color --no-pager --no-emoji -h --help"
    local output_opts="--format -o --output --json -q --quiet"
    local scan_opts="--profile -Pn --no-ping --correlate --since --save-xml"
    local logs_opts="-u --unit -p --priority --since --until -g --grep -n --lines -f --follow"

    local profiles="fast standard full"
    local formats="table json csv"
    local priorities="0 1 2 3 4 5 6 7 emerg alert crit err warning notice info debug"
    local ranges="15m 1h 6h 24h 7d today yesterday hoy ayer"

    # Localiza el subcomando: la primera palabra que no es una opción.
    subcommand=""
    for ((index = 1; index < COMP_CWORD; index++)); do
        case "${COMP_WORDS[index]}" in
            scan | logs)
                subcommand="${COMP_WORDS[index]}"
                break
                ;;
        esac
    done

    # Valor esperado por la opción anterior. Cada subcomando completa solo
    # los valores de sus propias opciones.
    case "$subcommand:$prev" in
        scan:--profile)
            mapfile -t COMPREPLY < <(compgen -W "$profiles" -- "$cur")
            return
            ;;
        scan:--format | logs:--format)
            mapfile -t COMPREPLY < <(compgen -W "$formats" -- "$cur")
            return
            ;;
        logs:-p | logs:--priority)
            mapfile -t COMPREPLY < <(compgen -W "$priorities" -- "$cur")
            return
            ;;
        scan:--since | logs:--since)
            mapfile -t COMPREPLY < <(compgen -W "$ranges" -- "$cur")
            return
            ;;
        logs:-u | logs:--unit)
            mapfile -t COMPREPLY < <(compgen -W "$(_suize_units)" -- "$cur")
            return
            ;;
        *:--config | *:-o | *:--output | scan:--save-xml | logs:--until | logs:-g | logs:--grep | logs:-n | logs:--lines)
            mapfile -t COMPREPLY < <(compgen -f -- "$cur")
            return
            ;;
    esac

    if [[ -z "$subcommand" ]]; then
        if [[ "$cur" == -* ]]; then
            mapfile -t COMPREPLY < <(compgen -W "$global_opts -V --version" -- "$cur")
        else
            mapfile -t COMPREPLY < <(compgen -W "scan logs" -- "$cur")
        fi
        return
    fi

    local opts="$global_opts $output_opts"
    case "$subcommand" in
        scan) opts="$opts $scan_opts" ;;
        logs) opts="$opts $logs_opts" ;;
    esac
    mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$cur")
}

complete -F _suize suize
