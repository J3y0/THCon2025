gef config context.enable 0

# Find main
start
break *0x5555555553b0
run THISISAPASSWORD

# At this address, we call ptrace for modifying idx_value
break *0x555555555517
commands 2
  silent
  printf "%d, ", $rcx
  continue
end

printf "idx values: 25, "
continue
