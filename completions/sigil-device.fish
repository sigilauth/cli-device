# fish completion for sigil-device

# Global options
complete -c sigil-device -s v -l version -d "Show version"

# Subcommands
complete -c sigil-device -f -n __fish_use_subcommand -a init -d "Initialize device identity"
complete -c sigil-device -f -n __fish_use_subcommand -a pair -d "Pair with Sigil server"
complete -c sigil-device -f -n __fish_use_subcommand -a register -d "Register with push relay"
complete -c sigil-device -f -n __fish_use_subcommand -a listen -d "Listen for push notifications"
complete -c sigil-device -f -n __fish_use_subcommand -a respond -d "Respond to auth challenge"
complete -c sigil-device -f -n __fish_use_subcommand -a mpa-respond -d "Respond to MPA challenge"
complete -c sigil-device -f -n __fish_use_subcommand -a decrypt -d "Decrypt ECIES payload"
complete -c sigil-device -f -n __fish_use_subcommand -a whoami -d "Display device identity"
complete -c sigil-device -f -n __fish_use_subcommand -a unpair -d "Remove device identity"

# pair command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from pair" -l server -d "Sigil server URL"

# register command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from register" -l relay -d "Push relay URL"

# listen command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from listen" -l relay -d "Push relay URL"
complete -c sigil-device -f -n "__fish_seen_subcommand_from listen" -l auto-approve -d "Auto-approve challenges"

# respond command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from respond" -l server -d "Sigil server URL"

# mpa-respond command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from mpa-respond" -l server -d "Sigil server URL"

# decrypt command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from decrypt" -l server -d "Sigil server URL"

# unpair command options
complete -c sigil-device -f -n "__fish_seen_subcommand_from unpair" -l server -d "Sigil server URL"
