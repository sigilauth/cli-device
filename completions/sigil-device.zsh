#compdef sigil-device

_sigil-device() {
    local -a commands
    commands=(
        'init:Initialize device identity'
        'pair:Pair with Sigil server'
        'register:Register with push relay'
        'listen:Listen for push notifications'
        'respond:Respond to auth challenge'
        'mpa-respond:Respond to MPA challenge'
        'decrypt:Decrypt ECIES payload'
        'whoami:Display device identity'
        'unpair:Remove device identity'
    )

    _arguments -C \
        '(- *)'{--version,-v}'[Show version]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                pair|respond|mpa-respond|decrypt|unpair)
                    _arguments \
                        '--server[Sigil server URL]:url:'
                    ;;
                register)
                    _arguments \
                        '--relay[Push relay URL]:url:'
                    ;;
                listen)
                    _arguments \
                        '--relay[Push relay URL]:url:' \
                        '--auto-approve[Auto-approve challenges]'
                    ;;
                init|whoami)
                    # No arguments
                    ;;
            esac
            ;;
    esac
}

_sigil-device "$@"
