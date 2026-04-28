# bash completion for sigil-device                        -*- shell-script -*-

_sigil-device()
{
    local cur prev words cword
    _init_completion || return

    local commands="init pair register listen respond mpa-respond decrypt whoami unpair"
    local global_opts="--version -v"

    # If we're completing the first argument, offer commands
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands} ${global_opts}" -- "$cur") )
        return
    fi

    # Get the command (first argument)
    local command="${words[1]}"

    # Command-specific completions
    case "$command" in
        pair|respond|mpa-respond|decrypt|unpair)
            case "$prev" in
                --server)
                    # Could complete with https:// but leaving empty for manual input
                    COMPREPLY=()
                    return
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "--server" -- "$cur") )
                    return
                    ;;
            esac
            ;;
        register)
            case "$prev" in
                --relay)
                    COMPREPLY=()
                    return
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "--relay" -- "$cur") )
                    return
                    ;;
            esac
            ;;
        listen)
            case "$prev" in
                --relay)
                    COMPREPLY=()
                    return
                    ;;
                *)
                    COMPREPLY=( $(compgen -W "--relay --auto-approve" -- "$cur") )
                    return
                    ;;
            esac
            ;;
        init|whoami)
            # No flags for these commands
            COMPREPLY=()
            return
            ;;
        --version|-v)
            # No further completion after version flag
            COMPREPLY=()
            return
            ;;
    esac
} &&
complete -F _sigil-device sigil-device

# ex: filetype=sh
