#!/usr/bin/env bash

# This file is licensed under the GPLv2+. Please see COPYING for more information.
# Record Store - Implementation of `password-store` for records.
# Near explicit copy/paste/replace of `password-store` - by Jason A. Donenfeld.

# Copyright (C) 2012 - 2018 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
# This file is licensed under the GPLv2+. Please see COPYING for more information.

umask "${RECORD_STORE_UMASK:-077}"
set -o pipefail

GPG_OPTS=( $RECORD_STORE_GPG_OPTS "--quiet" "--yes" "--compress-algo=none" "--no-encrypt-to" )
GPG="gpg"
export GPG_TTY="${GPG_TTY:-$(tty 2>/dev/null)}"
which gpg2 &>/dev/null && GPG="gpg2"
[[ -n $GPG_AGENT_INFO || $GPG == "gpg2" ]] && GPG_OPTS+=( "--batch" "--use-agent" )

PREFIX="${RECORD_STORE_DIR:-$HOME/.record-store}"
DESTINATION_PREFIX="${RECORD_DESTINAION_DIR:-$HOME/Documents}"
EXTENSIONS="${RECORD_STORE_EXTENSIONS_DIR:-$PREFIX/.extensions}"
X_SELECTION="${RECORD_STORE_X_SELECTION:-clipboard}"
CLIP_TIME="${RECORD_STORE_CLIP_TIME:-45}"
CHARACTER_SET="${RECORD_STORE_CHARACTER_SET:-[:graph:]}"
CHARACTER_SET_NO_SYMBOLS="${RECORD_STORE_CHARACTER_SET_NO_SYMBOLS:-[:alnum:]}"

export GIT_CEILING_DIRECTORIES="$PREFIX/.."

#
# BEGIN helper functions
#

set_git() {
	INNER_GIT_DIR="${1%/*}"
	while [[ ! -d $INNER_GIT_DIR && ${INNER_GIT_DIR%/*}/ == "${PREFIX%/}/"* ]]; do
		INNER_GIT_DIR="${INNER_GIT_DIR%/*}"
	done
	[[ $(git -C "$INNER_GIT_DIR" rev-parse --is-inside-work-tree 2>/dev/null) == true ]] || INNER_GIT_DIR=""
}
git_add_file() {
	[[ -n $INNER_GIT_DIR ]] || return
	git -C "$INNER_GIT_DIR" add "$1" || return
	[[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$1") ]] || return
	git_commit "$2"
}
git_commit() {
	local sign=""
	[[ -n $INNER_GIT_DIR ]] || return
	[[ $(git -C "$INNER_GIT_DIR" config --bool --get rec.signcommits) == "true" ]] && sign="-S"
	git -C "$INNER_GIT_DIR" commit $sign -m "$1"
}
yesno() {
	[[ -t 0 ]] || return 0
	local response
	read -r -p "$1 [y/N] " response
	[[ $response == [yY] ]] || exit 1
}
die() {
	echo "$@" >&2
	exit 1
}
verify_file() {
	[[ -n $RECORD_STORE_SIGNING_KEY ]] || return 0
	[[ -f $1.sig ]] || die "Signature for $1 does not exist."
	local fingerprints="$($GPG $RECORD_STORE_GPG_OPTS --verify --status-fd=1 "$1.sig" "$1" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG \([A-F0-9]\{40\}\) .* \([A-F0-9]\{40\}\)$/\1\n\2/p')"
	local fingerprint found=0
	for fingerprint in $RECORD_STORE_SIGNING_KEY; do
		[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || continue
		[[ $fingerprints == *$fingerprint* ]] && { found=1; break; }
	done
	[[ $found -eq 1 ]] || die "Signature for $1 is invalid."
}
set_gpg_recipients() {
	GPG_RECIPIENT_ARGS=( )
	GPG_RECIPIENTS=( )

	if [[ -n $RECORD_STORE_KEY ]]; then
		for gpg_id in $RECORD_STORE_KEY; do
			GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
			GPG_RECIPIENTS+=( "$gpg_id" )
		done
		return
	fi

	local current="$PREFIX/$1"
	while [[ $current != "$PREFIX" && ! -f $current/.gpg-id ]]; do
		current="${current%/*}"
	done
	current="$current/.gpg-id"

	if [[ ! -f $current ]]; then
		cat >&2 <<-_EOF
		Error: You must run:
		    $PROGRAM init your-gpg-id
		before you may use the record store.

		_EOF
		cmd_usage
		exit 1
	fi

	verify_file "$current"

	local gpg_id
	while read -r gpg_id; do
		GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
		GPG_RECIPIENTS+=( "$gpg_id" )
	done < "$current"
}

reencrypt_path() {
	local prev_gpg_recipients="" gpg_keys="" current_keys="" index recordfile
	local groups="$($GPG $RECORD_STORE_GPG_OPTS --list-config --with-colons | grep "^cfg:group:.*")"
	while read -r -d "" recordfile; do
		[[ -L $recordfile ]] && continue
		local recordfile_dir="${recfile%/*}"
		recordfile_dir="${recfile_dir#$PREFIX}"
		recordfile_dir="${recfile_dir#/}"
		local recordfile_display="${recfile#$PREFIX/}"
		recordfile_display="${recfile_display%.gpg}"
		local recordfile_temp="${recfile}.tmp.${RANDOM}.${RANDOM}.${RANDOM}.${RANDOM}.--"

		set_gpg_recipients "$recordfile_dir"
		if [[ $prev_gpg_recipients != "${GPG_RECIPIENTS[*]}" ]]; then
			for index in "${!GPG_RECIPIENTS[@]}"; do
				local group="$(sed -n "s/^cfg:group:$(sed 's/[\/&]/\\&/g' <<<"${GPG_RECIPIENTS[$index]}"):\\(.*\\)\$/\\1/p" <<<"$groups" | head -n 1)"
				[[ -z $group ]] && continue
				IFS=";" eval 'GPG_RECIPIENTS+=( $group )' # http://unix.stackexchange.com/a/92190
				unset "GPG_RECIPIENTS[$index]"
			done
			gpg_keys="$($GPG $RECORD_STORE_GPG_OPTS --list-keys --with-colons "${GPG_RECIPIENTS[@]}" | sed -n 's/^sub:[^idr:]*:[^:]*:[^:]*:\([^:]*\):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[a-zA-Z]*e[a-zA-Z]*:.*/\1/p' | LC_ALL=C sort -u)"
		fi
		current_keys="$(LC_ALL=C $GPG $RECORD_STORE_GPG_OPTS -v --no-secmem-warning --no-permission-warning --decrypt --list-only --keyid-format long "$recordfile" 2>&1 | sed -n 's/^gpg: public key is \([A-F0-9]\+\)$/\1/p' | LC_ALL=C sort -u)"

		if [[ $gpg_keys != "$current_keys" ]]; then
			echo "$recordfile_display: reencrypting to ${gpg_keys//$'\n'/ }"
			$GPG -d "${GPG_OPTS[@]}" "$recordfile" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$recfile_temp" "${GPG_OPTS[@]}" &&
			mv "$recordfile_temp" "$recfile" || rm -f "$recordfile_temp"
		fi
		prev_gpg_recipients="${GPG_RECIPIENTS[*]}"
	done < <(find "$1" -path '*/.git' -prune -o -iname '*.gpg' -print0)
}
check_sneaky_paths() {
	local path
	for path in "$@"; do
		[[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] && die "Error: You've attempted to rec a sneaky path to rec. Go home."
	done
}

#
# END helper functions
#

#
# BEGIN platform definable
#

clip() {
	if [[ -n $WAYLAND_DISPLAY ]]; then
		local copy_cmd=( wl-copy )
		local paste_cmd=( wl-paste -n )
		if [[ $X_SELECTION == primary ]]; then
			copy_cmd+=( --primary )
			paste_cmd+=( --primary )
		fi
		local display_name="$WAYLAND_DISPLAY"
	elif [[ -n $DISPLAY ]]; then
		local copy_cmd=( xclip -selection "$X_SELECTION" )
		local paste_cmd=( xclip -o -selection "$X_SELECTION" )
		local display_name="$DISPLAY"
	else
		die "Error: No X11 or Wayland display detected"
	fi
	local sleep_argv0="record store sleep on display $display_name"

	# This base64 business is because bash cannot store binary data in a shell
	# variable. Specifically, it cannot store nulls nor (non-trivally) store
	# trailing new lines.
	pkill -f "^$sleep_argv0" 2>/dev/null && sleep 0.5
	local before="$("${paste_cmd[@]}" 2>/dev/null | $BASE64)"
	echo -n "$1" | "${copy_cmd[@]}" || die "Error: Could not copy data to the clipboard"
	(
		( exec -a "$sleep_argv0" bash <<<"trap 'kill %1' TERM; sleep '$CLIP_TIME' & wait" )
		local now="$("${paste_cmd[@]}" | $BASE64)"
		[[ $now != $(echo -n "$1" | $BASE64) ]] && before="$now"

		# It might be nice to programatically check to see if klipper exists,
		# as well as checking for other common clipboard managers. But for now,
		# this works fine -- if qdbus isn't there or if klipper isn't running,
		# this essentially becomes a no-op.
		#
		# Clipboard managers frequently write their history out in plaintext,
		# so we axe it here:
		qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory &>/dev/null

		echo "$before" | $BASE64 -d | "${copy_cmd[@]}"
	) >/dev/null 2>&1 & disown
	echo "Copied $2 to clipboard. Will clear in $CLIP_TIME seconds."
}

qrcode() {
	if [[ -n $DISPLAY || -n $WAYLAND_DISPLAY ]]; then
		if type feh >/dev/null 2>&1; then
			echo -n "$1" | qrencode --size 10 -o - | feh -x --title "rec: $2" -g +200+200 -
			return
		elif type gm >/dev/null 2>&1; then
			echo -n "$1" | qrencode --size 10 -o - | gm display -title "rec: $2" -geometry +200+200 -
			return
		elif type display >/dev/null 2>&1; then
			echo -n "$1" | qrencode --size 10 -o - | display -title "rec: $2" -geometry +200+200 -
			return
		fi
	fi
	echo -n "$1" | qrencode -t utf8
}

tmpdir() {
	[[ -n $SECURE_TMPDIR ]] && return
	local warn=1
	[[ $1 == "nowarn" ]] && warn=0
	local template="$PROGRAM.XXXXXXXXXXXXX"
	if [[ -d /dev/shm && -w /dev/shm && -x /dev/shm ]]; then
		SECURE_TMPDIR="$(mktemp -d "/dev/shm/$template")"
		remove_tmpfile() {
			rm -rf "$SECURE_TMPDIR"
		}
		trap remove_tmpfile EXIT
	else
		[[ $warn -eq 1 ]] && yesno "$(cat <<-_EOF
		Your system does not have /dev/shm, which means that it may
		be difficult to entirely erase the temporary non-encrypted
		record file after editing.

		Are you sure you would like to continue?
		_EOF
		)"
		SECURE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/$template")"
		shred_tmpfile() {
			find "$SECURE_TMPDIR" -type f -exec $SHRED {} +
			rm -rf "$SECURE_TMPDIR"
		}
		trap shred_tmpfile EXIT
	fi

}
GETOPT="getopt"
SHRED="shred -f -z"
BASE64="base64"

source "$(dirname "$0")/platform/$(uname | cut -d _ -f 1 | tr '[:upper:]' '[:lower:]').sh" 2>/dev/null # PLATFORM_FUNCTION_FILE

#
# END platform definable
#


#
# BEGIN subcommand functions
#

cmd_version() {
	cat <<-_EOF
	============================================
	=  rec:  the standard unix record manager  =
	=                                          =
	=                  v1.7.3                  =
	=                                          =
	=		Copied of Works		   =
	=             Jason A. Donenfeld           =
	=               Jason@zx2c4.com            =
	=                                          =
	=      http://www.passwordstore.org/       =
	============================================
	_EOF
}

cmd_usage() {
	cmd_version
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM init [--path=subfolder,-p subfolder] gpg-id...
	        Initialize new record storage and use gpg-id for encryption.
	        Selectively reencrypt existing records using new gpg-id.
	    $PROGRAM [ls] [subfolder]
	        List records.
	    $PROGRAM find record-names...
	    	List records that match record-names.
	    $PROGRAM [show] [--clip[=line-number],-c[line-number]] record-name
	        Show existing record and optionally put it on the clipboard.
	        If put on the clipboard, it will be cleared in $CLIP_TIME seconds.
	    $PROGRAM grep [GREPOPTIONS] search-string
	        Search for record files containing search-string when decrypted.
	    $PROGRAM insert [--force,-f] record-name
	        Insert new record. Prompt before overwriting existing record unless
		forced.
	    $PROGRAM edit record-name
	        Insert a new record or edit an existing record using ${EDITOR:-vi}.
	    $PROGRAM rm [--recursive,-r] [--force,-f] record-name
	        Remove existing record or directory, optionally forcefully.
	    $PROGRAM mv [--force,-f] old-path new-path
	        Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM cp [--force,-f] old-path new-path
	        Copies old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM git git-command-args...
	        If the record store is a git repository, execute a git command
	        specified by git-command-args.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM version
	        Show version information.

	More information may be found in the rec(1) man page.
	_EOF
}

cmd_init() {
	local opts id_path=""
	opts="$($GETOPT -o p: -l path: -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-p|--path) id_path="$2"; shift 2 ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 || $# -lt 1 ]] && die "Usage: $PROGRAM $COMMAND [--path=subfolder,-p subfolder] gpg-id..."
	[[ -n $id_path ]] && check_sneaky_paths "$id_path"
	[[ -n $id_path && ! -d $PREFIX/$id_path && -e $PREFIX/$id_path ]] && die "Error: $PREFIX/$id_path exists but is not a directory."

	local gpg_id="$PREFIX/$id_path/.gpg-id"
	set_git "$gpg_id"

	if [[ $# -eq 1 && -z $1 ]]; then
		[[ ! -f "$gpg_id" ]] && die "Error: $gpg_id does not exist and so cannot be removed."
		rm -v -f "$gpg_id" || exit 1
		if [[ -n $INNER_GIT_DIR ]]; then
			git -C "$INNER_GIT_DIR" rm -qr "$gpg_id"
			git_commit "Deinitialize ${gpg_id}${id_path:+ ($id_path)}."
		fi
		rmdir -p "${gpg_id%/*}" 2>/dev/null
	else
		mkdir -p "$PREFIX/$id_path"
		printf "%s\n" "$@" > "$gpg_id"
		local id_print="$(printf "%s, " "$@")"
		echo "word store initialized for ${id_print%, }${id_path:+ ($id_path)}"
		git_add_file "$gpg_id" "Set GPG id to ${id_print%, }${id_path:+ ($id_path)}."
		if [[ -n $RECORD_STORE_SIGNING_KEY ]]; then
			local signing_keys=( ) key
			for key in $RECORD_STORE_SIGNING_KEY; do
				signing_keys+=( --default-key $key )
			done
			$GPG "${GPG_OPTS[@]}" "${signing_keys[@]}" --detach-sign "$gpg_id" || die "Could not sign .gpg_id."
			key="$($GPG --verify --status-fd=1 "$gpg_id.sig" "$gpg_id" 2>/dev/null | sed -n 's/^\[GNUPG:\] VALIDSIG [A-F0-9]\{40\} .* \([A-F0-9]\{40\}\)$/\1/p')"
			[[ -n $key ]] || die "Signing of .gpg_id unsuccessful."
			git_add_file "$gpg_id.sig" "Signing new GPG id with ${key//[$IFS]/,}."
		fi
	fi

	reencrypt_path "$PREFIX/$id_path"
	git_add_file "$PREFIX/$id_path" "Reencrypt record store using new GPG id ${id_print%, }${id_path:+ ($id_path)}."
}

cmd_show() {
	local opts selected_line clip=0 qrcode=0
	opts="$($GETOPT -o q::c:: -l qrcode::,clip:: -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-q|--qrcode) qrcode=1; selected_line="${2:-1}"; shift 2 ;;
		-c|--clip) clip=1; selected_line="${2:-1}"; shift 2 ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND [record-name]"

	local rec
	local path="$1"
	local recordfile="$PREFIX/$path.gpg"
	check_sneaky_paths "$path"
	if [[ -f $recordfile ]]; then
		rec="$($GPG -d "${GPG_OPTS[@]}" "$recordfile" > "$DESTINATION_PREFIX/record")" || exit $?
		echo exported to \"~/documents/record\"
		#echo "$rec" | $BASE64 -d
	elif [[ -d $PREFIX/$path ]]; then
		if [[ -z $path ]]; then
			echo "word Store"
		else
			echo "${path%\/}"
		fi
		tree -l "$PREFIX/$path" | tail -n +2 | sed -E 's/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g' # remove .gpg at end of line, but keep colors
	elif [[ -z $path ]]; then
		die "Error: record store is empty. Try \"rec init\"."
	else
		die "Error: $path is not in the record store."
	fi
}

cmd_find() {
	[[ $# -eq 0 ]] && die "Usage: $PROGRAM $COMMAND record-names..."
	IFS="," eval 'echo "Search Terms: $*"'
	local terms="*$(printf '%s*|*' "$@")"
	tree -l -P "${terms%|*}" --prune --matchdirs --ignore-case "$PREFIX" | tail -n +2 | sed -E 's/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
}

cmd_grep() {
	[[ $# -lt 1 ]] && die "Usage: $PROGRAM $COMMAND [GREPOPTIONS] search-string"
	local recordfile grepresults
	while read -r -d "" recordfile; do
		grepresults="$($GPG -d "${GPG_OPTS[@]}" "$recordfile" | grep --color=always "$@")"
		[[ $? -ne 0 ]] && continue
		recordfile="${recfile%.gpg}"
		recordfile="${recfile#$PREFIX/}"
		local recordfile_dir="${recfile%/*}/"
		[[ $recordfile_dir == "${recfile}/" ]] && recordfile_dir=""
		recordfile="${recfile##*/}"
		printf "\e[94m%s\e[1m%s\e[0m:\n" "$recordfile_dir" "$recfile"
		echo "$grepresults"
	done < <(find -L "$PREFIX" -path '*/.git' -prune -o -iname '*.gpg' -print0)
}

cmd_insert() {
	local opts force=0
	opts="$($GETOPT -o mef -l force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 || $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND [--force,-f] record-name"
	local path="${1%/}"
	local recordfile="$PREFIX/$path.gpg"
	check_sneaky_paths "$path"
	set_git "$recordfile"

	[[ $force -eq 0 && -e $recordfile ]] && yesno "An entry already exists for $path. Overwrite it?"

	mkdir -p "$PREFIX/$(dirname -- "$path")"
	set_gpg_recipients "$(dirname -- "$path")"

	local record
	read -r -p "Enter path, and file name for record at $path: " -e record
	$GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$recordfile" "${GPG_OPTS[@]}" "$record" || die "record encryption aborted."

	git_add_file "$recordfile" "Add given record for $path to store."
}

cmd_edit() {
	[[ $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND record-name"

	local path="${1%/}"
	check_sneaky_paths "$path"
	mkdir -p "$PREFIX/$(dirname -- "$path")"
	set_gpg_recipients "$(dirname -- "$path")"
	local recordfile="$PREFIX/$path.gpg"
	set_git "$recordfile"

	tmpdir #Defines $SECURE_TMPDIR
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt"

	local action="Add"
	if [[ -f $recordfile ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$recordfile" || exit 1
		action="Edit"
	fi
	${EDITOR:-vi} "$tmp_file"
	[[ -f $tmp_file ]] || die "New record not saved."
	$GPG -d -o - "${GPG_OPTS[@]}" "$recordfile" 2>/dev/null | diff - "$tmp_file" &>/dev/null && die "record unchanged."
	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$recordfile" "${GPG_OPTS[@]}" "$tmp_file"; do
		yesno "GPG encryption failed. Would you like to try again?"
	done
	git_add_file "$recordfile" "$action record for $path using ${EDITOR:-vi}."
}

cmd_delete() {
	local opts recursive="" force=0
	opts="$($GETOPT -o rf -l recursive,force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-r|--recursive) recursive="-r"; shift ;;
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done
	[[ $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND [--recursive,-r] [--force,-f] record-name"
	local path="$1"
	check_sneaky_paths "$path"

	local recdir="$PREFIX/${path%/}"
	local recordfile="$PREFIX/$path.gpg"
	[[ -f $recordfile && -d $recdir && $path == */ || ! -f $recordfile ]] && recfile="${recdir%/}/"
	[[ -e $recordfile ]] || die "Error: $path is not in the record store."
	set_git "$recordfile"

	[[ $force -eq 1 ]] || yesno "Are you sure you would like to delete $path?"

	rm $recursive -f -v "$recordfile"
	set_git "$recordfile"
	if [[ -n $INNER_GIT_DIR && ! -e $recordfile ]]; then
		git -C "$INNER_GIT_DIR" rm -qr "$recordfile"
		set_git "$recordfile"
		git_commit "Remove $path from store."
	fi
	rmdir -p "${recordfile%/*}" 2>/dev/null
}

cmd_copy_move() {
	local opts move=1 force=0
	[[ $1 == "copy" ]] && move=0
	shift
	opts="$($GETOPT -o f -l force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done
	[[ $# -ne 2 ]] && die "Usage: $PROGRAM $COMMAND [--force,-f] old-path new-path"
	check_sneaky_paths "$@"
	local old_path="$PREFIX/${1%/}"
	local old_dir="$old_path"
	local new_path="$PREFIX/$2"

	if ! [[ -f $old_path.gpg && -d $old_path && $1 == */ || ! -f $old_path.gpg ]]; then
		old_dir="${old_path%/*}"
		old_path="${old_path}.gpg"
	fi
	echo "$old_path"
	[[ -e $old_path ]] || die "Error: $1 is not in the record store."

	mkdir -p "${new_path%/*}"
	[[ -d $old_path || -d $new_path || $new_path == */ ]] || new_path="${new_path}.gpg"

	local interactive="-i"
	[[ ! -t 0 || $force -eq 1 ]] && interactive="-f"

	set_git "$new_path"
	if [[ $move -eq 1 ]]; then
		mv $interactive -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"

		set_git "$new_path"
		if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
			git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
			set_git "$new_path"
			git_add_file "$new_path" "Rename ${1} to ${2}."
		fi
		set_git "$old_path"
		if [[ -n $INNER_GIT_DIR && ! -e $old_path ]]; then
			git -C "$INNER_GIT_DIR" rm -qr "$old_path" 2>/dev/null
			set_git "$old_path"
			[[ -n $(git -C "$INNER_GIT_DIR" status --porcelain "$old_path") ]] && git_commit "Remove ${1}."
		fi
		rmdir -p "$old_dir" 2>/dev/null
	else
		cp $interactive -r -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"
		git_add_file "$new_path" "Copy ${1} to ${2}."
	fi
}

cmd_git() {
	set_git "$PREFIX/"
	if [[ $1 == "init" ]]; then
		INNER_GIT_DIR="$PREFIX"
		git -C "$INNER_GIT_DIR" "$@" || exit 1
		git_add_file "$PREFIX" "Add current contents of record store."

		echo '*.gpg diff=gpg' > "$PREFIX/.gitattributes"
		git_add_file .gitattributes "Configure git repository for gpg file diff."
		git -C "$INNER_GIT_DIR" config --local diff.gpg.binary true
		git -C "$INNER_GIT_DIR" config --local diff.gpg.textconv "$GPG -d ${GPG_OPTS[*]}"
	elif [[ -n $INNER_GIT_DIR ]]; then
		tmpdir nowarn #Defines $SECURE_TMPDIR. We don't warn, because at most, this only copies encrypted files.
		export TMPDIR="$SECURE_TMPDIR"
		git -C "$INNER_GIT_DIR" "$@"
	else
		die "Error: the record store is not a git repository. Try \"$PROGRAM git init\"."
	fi
}

cmd_extension_or_show() {
	if ! cmd_extension "$@"; then
		COMMAND="show"
		cmd_show "$@"
	fi
}

SYSTEM_EXTENSION_DIR=""
cmd_extension() {
	check_sneaky_paths "$1"
	local user_extension system_extension extension
	[[ -n $SYSTEM_EXTENSION_DIR ]] && system_extension="$SYSTEM_EXTENSION_DIR/$1.bash"
	[[ $RECORD_STORE_ENABLE_EXTENSIONS == true ]] && user_extension="$EXTENSIONS/$1.bash"
	if [[ -n $user_extension && -f $user_extension && -x $user_extension ]]; then
		verify_file "$user_extension"
		extension="$user_extension"
	elif [[ -n $system_extension && -f $system_extension && -x $system_extension ]]; then
		extension="$system_extension"
	else
		return 1
	fi
	shift
	source "$extension" "$@"
	return 0
}

#
# END subcommand functions
#

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
	init) shift;			cmd_init "$@" ;;
	help|--help) shift;		cmd_usage "$@" ;;
	version|--version) shift;	cmd_version "$@" ;;
	show|ls|list) shift;		cmd_show "$@" ;;
	find|search) shift;		cmd_find "$@" ;;
	grep) shift;			cmd_grep "$@" ;;
	insert|add) shift;		cmd_insert "$@" ;;
	edit) shift;			cmd_edit "$@" ;;
	delete|rm|remove) shift;	cmd_delete "$@" ;;
	rename|mv) shift;		cmd_copy_move "move" "$@" ;;
	copy|cp) shift;			cmd_copy_move "copy" "$@" ;;
	git) shift;			cmd_git "$@" ;;
	*)				cmd_extension_or_show "$@" ;;
esac
exit 0
