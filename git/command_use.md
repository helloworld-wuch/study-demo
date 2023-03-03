1、由于代码重合导致的push失败，需要先拉取远程分支再合并
git stash
git pull ...
git stash pop

2、删除不想要的远程分支main(注意 main必须非默认分支)
git  push -f  origin  --delete main

3、想要全部清空并更新到最新代码，不保留本地修改
git fetch origin 
git clean -f 
git reset --hard origin/master

4、commit后还没push，想要修改commit的信息
git commit --amend

5、commit后已经push了，但是还想改之前commit的信息
git log --oneline    #通过这个找到对应的SHA-1 校验和
git checkout <commit-SHA>
git commit --amend
git push --force origin <branch-name>

6、若出现ssh_exchange_identification: Connection closed by remote host，则重启sshd
service sshd restart


