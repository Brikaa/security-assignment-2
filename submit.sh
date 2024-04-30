if [[ `git status --porcelain` ]]; then
    echo "Uncommitted changes, aborting" && exit 1
fi
git clean -xfd
rm -rf ./submission && echo "Removed submission directory (if any)" || exit 1
mkdir -p ./submission/S5_Omar-Adel-Brikaa_20206043 && echo "Created a submission directory" || exit 1
cd report && echo "Preparing to compile the PDF" || exit 1
./convert.sh && echo "Created the PDF" || exit 1
cd ../submission/S5_Omar-Adel-Brikaa_20206043 || exit 1
cp -r ../../report/report.pdf ../../src/ . && echo "Copied the files into the submission directory" || exit 1
cd ../ || exit 1
zip -r S5_Omar-Adel-Brikaa_20206043.zip S5_Omar-Adel-Brikaa_20206043/ && echo "Zipped the submission directory" || exit 1
