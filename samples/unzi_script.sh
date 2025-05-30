for file in *.zip; do
  7z x $file -p"infected" -o"./"
done

