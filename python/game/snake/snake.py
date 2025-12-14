import pygame
import random

#准备画布
pygame.init()#初始化
GRID_SIZE = 20
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
GRID_WIDTH = SCREEN_WIDTH // GRID_SIZE
GRID_HEIGHT = SCREEN_HEIGHT // GRID_SIZE

screen = pygame.display.set_mode((SCREEN_WIDTH , SCREEN_HEIGHT))
clock = pygame.time.Clock()
#定义主要参数
food_pos = (random.randint(0, GRID_WIDTH - 1),
            random.randint(0, GRID_HEIGHT - 1))
snake_body = [(20,15), (19,15), (18,15)]
direction = (1,0)
score = 0
game_over = False
font = pygame.font.Font(None, 36)
#定义游戏初始化
def init_game():
    global snake_body,score,direction,food_pos,game_over
    snake_body = [(20,15), (19,15), (18,15)]
    score = 0
    game_over = False
    direction = (1,0)
    food_pos = (random.randint(0,GRID_WIDTH-1),
                random.randint(0,GRID_HEIGHT-1))
    #如果生成重合，那么重新生成
    while food_pos in snake_body:
        food_pos = (random.randint(0, GRID_WIDTH - 1),
                    random.randint(0, GRID_HEIGHT - 1))


init_game()
#程序开始运行
running = True
while running:

    #定义控制键逻辑
    for event in pygame.event.get():
        #检测按键控制退出
        if event.type == pygame.QUIT:
            running = False
        #检测按键控制移动
        if event.type == pygame.KEYDOWN:
            if game_over == True and event.key == pygame.K_r:
                init_game()
            elif not game_over:
                if event.key == pygame.K_UP:
                    if direction != (0,1):
                        direction = (0,-1)
                if event.key == pygame.K_DOWN:
                    if direction != (0, -1):
                        direction = (0, 1)
                if event.key == pygame.K_LEFT:
                    if direction != (1, 0):
                        direction = (-1, 0)
                if event.key == pygame.K_RIGHT:
                    if direction != (-1, 0):
                        direction = (1, 0)
    #定义旧的脑袋和没吃到食物正常行走的身体
    if not game_over:
        old_head = snake_body[0]
        new_x = old_head[0] + direction[0]
        new_y = old_head[1] + direction[1]
        new_head = (new_x, new_y)
        snake_body = [new_head] + snake_body[:-1]
        #判断脑袋撞到自己
        if new_head in snake_body[1:]:
            game_over = True
        #判断吃到食物之后的身体
        if new_head == food_pos:
            food_pos = (random.randint(0, GRID_WIDTH - 1),
                        random.randint(0, GRID_HEIGHT - 1))
            snake_body = [new_head] + snake_body
            #同时分数+10
            score += 10
        #判断脑袋超出屏幕之后的行为
        if new_head[0] > GRID_WIDTH or new_head[0] < 0 or new_head[1] > GRID_HEIGHT or new_head[1] < 0:
            game_over = True

    #绘制屏幕背景为黑色
    screen.fill((0,0,0))
    if not game_over:
        #绘制蛇图像
        for (grid_x,grid_y) in snake_body:

            pixel_x = grid_x * GRID_SIZE
            pixel_y = grid_y * GRID_SIZE

            pygame.draw.rect(
                screen,
                (0,255,0),
                (pixel_x,pixel_y,GRID_SIZE,GRID_SIZE)
            )
        #绘制食物图像
        food_pixel_x = food_pos[0] *GRID_SIZE
        food_pixel_y = food_pos[1] *GRID_SIZE
        pygame.draw.rect(
            screen,
            (255,0,0),
            (food_pixel_x,food_pixel_y,GRID_SIZE,GRID_SIZE)
        )
        #绘制分数
        score_text = font.render(f"Score:{score}",True,(255,255,255))
        screen.blit(score_text,(10,10))
        #添加游戏结束画面
    elif game_over:
        game_over_text = font.render("Game Over",True,(255,0,0))
        screen.blit(game_over_text,(SCREEN_WIDTH//2 - 80 ,SCREEN_HEIGHT//2 - 80))
        final_score_text = font.render(f"your score is :{score}",True,(255,255,255))
        screen.blit(final_score_text,(SCREEN_WIDTH//2 - 80,SCREEN_HEIGHT//2))
        restart_text = font.render("Please press R to restart",True,(200,200,200))
        screen.blit(restart_text,(SCREEN_WIDTH//2 - 100,SCREEN_HEIGHT//2 + 50))
    #刷新画面
    pygame.display.flip()

    clock.tick(20)

pygame.quit()