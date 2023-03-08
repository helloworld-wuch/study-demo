1、由于代码重合导致的push失败，需要先拉取远程分支再合并
git stash
git pull ...
git stash pop

2、删除不想要的远程分支main(注意 main必须非默认分支)
git  push -f  origin  --delete main

3、想要全部清空并更新到最新代码，不保留本地修改
git fetch origin 
git clean -f 
git reset --hard origin/master #可以是指定的版本

4、commit后还没push，想要修改commit的信息
git commit --amend

5、commit后已经push了，但是还想改之前commit的信息
git log --oneline    #通过这个找到对应的SHA-1 校验和
git checkout <commit-SHA>
git commit --amend
git push --force origin <branch-name>

6、若出现ssh_exchange_identification: Connection closed by remote host，则重启sshd
service sshd restart

7、提交子项目的修改内容
    ①进入子项目          cd child_project/
    ②添加修改的文件      git add modified_file.txt
    ③提交修改的标题      git commit -m "Added new feature to subproject"
    ④推送到子项目上      git push origin master
    ⑤进入主项目          cd main_project/
    ⑥添加修改的子项目    git add child_project
    ⑦提交修改的标签      git commit -m "Added new feature to project"
    ⑧推送到主项目        git push origin master

8、报错：error: src refspec xxx does not match any / error: failed to push some refs to解决
该问题是由于本地分支和push分支无法关联，可以将本地分支名改成远程push分支名即可

9、撤销对子项目的
git submodule foreach --recursive git checkout .

10、删除子项目目录并重新拉取分支
rm -r {submoudle_path}
git submodule update --init --recursive

11、


